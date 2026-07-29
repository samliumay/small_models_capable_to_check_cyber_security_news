from __future__ import annotations

import unittest
from unittest.mock import patch
from unittest.mock import Mock

import requests

from ollama.cyber_security_tools import CyberSecurityTools
from ollama.ollama_local_model_managment_code import OllamaLocalModelManagement


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.text)


class ToolTests(unittest.TestCase):
    def test_all_schemas_have_registered_function(self):
        tools = CyberSecurityTools()
        names = {item["function"]["name"] for item in tools.schemas}
        self.assertEqual(names, set(tools.available_functions))

    def test_invalid_cve_is_rejected_without_network(self):
        tools = CyberSecurityTools(session=Mock())
        result = tools.cve_detayi_getir("not-a-cve")
        self.assertIn("hata", result)
        tools.session.get.assert_not_called()

    def test_nvd_normalization(self):
        result = CyberSecurityTools._normalize_nvd(
            {
                "id": "CVE-2026-1234",
                "published": "2026-01-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Example flaw"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N",
                            }
                        }
                    ]
                },
            }
        )
        self.assertEqual(result["cve_id"], "CVE-2026-1234")
        self.assertEqual(result["cvss_puani"], 9.8)

    @patch.dict("os.environ", {}, clear=True)
    def test_news_failure_returns_official_advisory_fallback(self):
        session = Mock()
        session.get.side_effect = requests.Timeout("test timeout")
        tools = CyberSecurityTools(session=session)
        tools.guvenlik_duyurularini_getir = Mock(
            return_value={"sonuclar": [{"kaynak": "CISA"}], "hatalar": []}
        )

        result = tools.siber_haberlerini_ara("ransomware", 24, 5)

        self.assertEqual(
            result["alternatif_resmi_duyurular"]["sonuclar"][0]["kaynak"], "CISA"
        )
        self.assertIn("haber değil", result["uyari"])


class AgentLoopTests(unittest.TestCase):
    def test_multi_round_tool_call_and_final_answer(self):
        session = Mock()
        session.post.side_effect = [
            FakeResponse(
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "ornek_arac",
                                    "arguments": {"sorgu": "CVE"},
                                }
                            }
                        ],
                    },
                    "prompt_eval_count": 10,
                    "eval_count": 2,
                    "total_duration": 1_000_000_000,
                }
            ),
            FakeResponse(
                {
                    "message": {
                        "role": "assistant",
                        "content": "Türkçe nihai yanıt.",
                    },
                    "prompt_eval_count": 42,
                    "eval_count": 8,
                    "total_duration": 2_000_000_000,
                }
            ),
        ]
        tools = Mock()
        tools.schemas = []
        tools.execute.return_value = {"sonuclar": ["CVE-2026-1234"]}
        tools.to_json.side_effect = CyberSecurityTools.to_json
        agent = OllamaLocalModelManagement(
            session=session, tools=tools, model_name="test-model"
        )

        events = list(agent.run("En son CVE nedir?"))

        self.assertEqual([event["type"] for event in events], ["tool", "final"])
        self.assertEqual(events[0]["name"], "ornek_arac")
        self.assertEqual(events[1]["content"], "Türkçe nihai yanıt.")
        self.assertEqual(events[1]["metrics"]["prompt_tokens"], 52)
        self.assertEqual(events[1]["metrics"]["response_tokens"], 10)
        self.assertEqual(events[1]["metrics"]["total_tokens"], 62)
        self.assertEqual(events[1]["metrics"]["total_duration_seconds"], 3.0)
        second_messages = session.post.call_args_list[1].kwargs["json"]["messages"]
        self.assertEqual(second_messages[-1]["role"], "tool")
        self.assertEqual(second_messages[-1]["tool_name"], "ornek_arac")
        options = session.post.call_args_list[0].kwargs["json"]["options"]
        self.assertEqual(options["top_k"], 20)
        self.assertEqual(options["top_p"], 0.95)

    def test_missing_model_is_pulled_once(self):
        session = Mock()
        session.get.side_effect = [
            FakeResponse({"models": []}),
            FakeResponse({"models": []}),
        ]
        session.post.return_value = FakeResponse({"status": "success"})
        agent = OllamaLocalModelManagement(
            session=session,
            tools=Mock(),
            model_name="qwen3.5:4b",
        )

        result = agent.ensure_model()

        self.assertTrue(result["downloaded"])
        pull_payload = session.post.call_args.kwargs["json"]
        self.assertEqual(pull_payload, {"model": "qwen3.5:4b", "stream": False})


if __name__ == "__main__":
    unittest.main()
