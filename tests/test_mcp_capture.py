import unittest
from pathlib import Path

from rope_bench.mcp_capture import (
    _profile_draft,
    _resolve_dynamic_values,
    load_server_config,
)
from rope_core.model import SideEffect, SinkClass


ROOT = Path(__file__).resolve().parents[1]


class MCPCaptureConfigTests(unittest.TestCase):
    def test_paper_v1_config_loads_servers_without_live_processes(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        by_id = {server.server_id: server for server in servers}

        self.assertIn("filesystem", by_id)
        self.assertIn("memory", by_id)
        self.assertIn("git", by_id)
        self.assertIn("fetch", by_id)
        self.assertIn("sqlite", by_id)
        self.assertIn("github", by_id)
        self.assertIn("slack", by_id)
        self.assertIn("notion", by_id)
        self.assertIn("google_drive", by_id)
        self.assertIn("playwright_browser", by_id)
        self.assertIn("discord", by_id)
        self.assertEqual(
            by_id["github"].requires_env,
            ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TEST_OWNER", "GITHUB_TEST_REPO"),
        )
        self.assertGreaterEqual(len(by_id["github"].sample_calls), 4)
        self.assertEqual(
            by_id["slack"].requires_env,
            ("SLACK_BOT_TOKEN", "SLACK_TEAM_ID", "SLACK_CHANNEL_ID"),
        )
        self.assertGreaterEqual(len(by_id["slack"].sample_calls), 3)
        self.assertEqual(by_id["notion"].requires_env, ("NOTION_TOKEN", "NOTION_PAGE_ID"))
        self.assertGreaterEqual(len(by_id["notion"].sample_calls), 3)
        self.assertEqual(
            by_id["google_drive"].requires_env,
            ("GOOGLE_DRIVE_TEST_FOLDER_ID",),
        )
        self.assertEqual(
            by_id["google_drive"].requires_one_of_env,
            (("GOOGLE_OAUTH_TOKEN",), ("GOOGLE_APPLICATION_CREDENTIALS",)),
        )
        self.assertGreaterEqual(len(by_id["google_drive"].sample_calls), 3)
        self.assertGreaterEqual(len(by_id["playwright_browser"].sample_calls), 4)
        self.assertEqual(
            by_id["discord"].requires_env,
            ("DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID"),
        )

    def test_sample_call_dynamic_values_resolve_from_environment(self):
        import os

        old_owner = os.environ.get("GITHUB_TEST_OWNER")
        old_repo = os.environ.get("GITHUB_TEST_REPO")
        try:
            os.environ["GITHUB_TEST_OWNER"] = "alice"
            os.environ["GITHUB_TEST_REPO"] = "rope-mcp-test"
            value = {
                "owner": "${ENV:GITHUB_TEST_OWNER}",
                "repo": "${ENV:GITHUB_TEST_REPO}",
                "path": "rope-capture/write-test-{run_stamp}.md",
                "files": [{"content": "stamp {run_stamp}"}],
            }
            resolved = _resolve_dynamic_values(value, "20260525120000")
        finally:
            if old_owner is None:
                os.environ.pop("GITHUB_TEST_OWNER", None)
            else:
                os.environ["GITHUB_TEST_OWNER"] = old_owner
            if old_repo is None:
                os.environ.pop("GITHUB_TEST_REPO", None)
            else:
                os.environ["GITHUB_TEST_REPO"] = old_repo

        self.assertEqual(resolved["owner"], "alice")
        self.assertEqual(resolved["repo"], "rope-mcp-test")
        self.assertEqual(resolved["path"], "rope-capture/write-test-20260525120000.md")
        self.assertEqual(resolved["files"][0]["content"], "stamp 20260525120000")

    def test_profile_draft_uses_rope_sink_and_side_effect_vocabularies(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        filesystem = next(server for server in servers if server.server_id == "filesystem")
        profile = _profile_draft(
            filesystem,
            {
                "name": "write_file",
                "description": "Write a local file.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"path": {}, "content": {}}},
            },
        )

        self.assertIn(profile["sink"], {sink.value for sink in SinkClass})
        self.assertIn(profile["side_effect"], {effect.value for effect in SideEffect})
        self.assertEqual(profile["sink"], SinkClass.LOCAL_FILE.value)
        self.assertEqual(profile["side_effect"], SideEffect.WRITE.value)
        self.assertEqual(profile["trust"], "server_hint")
        self.assertTrue(profile["requires_host_review"])

    def test_open_world_tool_is_captured_as_public_sink_hint(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        fetch = next(server for server in servers if server.server_id == "fetch")
        profile = _profile_draft(
            fetch,
            {
                "name": "fetch",
                "description": "Fetch a URL.",
                "annotations": {"openWorldHint": True, "readOnlyHint": True},
                "inputSchema": {"properties": {"url": {}}},
            },
        )

        self.assertEqual(profile["sink"], SinkClass.PUBLIC_WEB.value)
        self.assertEqual(profile["side_effect"], SideEffect.SEND.value)

    def test_create_names_are_classified_by_server_category_before_external_rules(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        filesystem = next(server for server in servers if server.server_id == "filesystem")
        memory = next(server for server in servers if server.server_id == "memory")

        directory_profile = _profile_draft(
            filesystem,
            {
                "name": "create_directory",
                "description": "Create a directory.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"path": {}}},
            },
        )
        memory_profile = _profile_draft(
            memory,
            {
                "name": "create_entities",
                "description": "Create memory graph entities.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"entities": {}}},
            },
        )

        self.assertEqual(directory_profile["sink"], SinkClass.LOCAL_FILE.value)
        self.assertEqual(memory_profile["sink"], SinkClass.INTERNAL_SERVICE.value)
        self.assertEqual(memory_profile["side_effect"], SideEffect.WRITE.value)

    def test_sqlite_write_query_is_conservative_destructive_write_hint(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        sqlite = next(server for server in servers if server.server_id == "sqlite")
        profile = _profile_draft(
            sqlite,
            {
                "name": "write_query",
                "description": "Execute an INSERT, UPDATE, or DELETE query.",
                "annotations": {},
                "inputSchema": {"properties": {"query": {}}},
            },
        )

        self.assertEqual(profile["sink"], SinkClass.DESTRUCTIVE_WRITE.value)
        self.assertEqual(profile["side_effect"], SideEffect.WRITE.value)

    def test_same_org_message_post_is_classified_as_message_sink(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        slack = next(server for server in servers if server.server_id == "slack")
        profile = _profile_draft(
            slack,
            {
                "name": "slack_post_message",
                "description": "Post a message to a Slack channel.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"channel_id": {}, "text": {}}},
            },
        )

        self.assertEqual(profile["sink"], SinkClass.SAME_ORG_MESSAGE.value)
        self.assertEqual(profile["side_effect"], SideEffect.SEND.value)

    def test_document_workspace_patch_is_classified_as_internal_write(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        notion = next(server for server in servers if server.server_id == "notion")
        profile = _profile_draft(
            notion,
            {
                "name": "API-patch-block-children",
                "description": "Append block children to a Notion page.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"block_id": {}, "children": {}}},
            },
        )

        self.assertEqual(profile["sink"], SinkClass.INTERNAL_SERVICE.value)
        self.assertEqual(profile["side_effect"], SideEffect.WRITE.value)

    def test_cloud_document_storage_write_is_classified_as_internal_write(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        gdrive = next(server for server in servers if server.server_id == "google_drive")
        profile = _profile_draft(
            gdrive,
            {
                "name": "gdrive_write_text_file",
                "description": "Create a text file in a Google Drive folder.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"folder_id": {}, "name": {}, "content": {}}},
            },
        )

        self.assertEqual(profile["sink"], SinkClass.INTERNAL_SERVICE.value)
        self.assertEqual(profile["side_effect"], SideEffect.WRITE.value)

    def test_browser_public_web_tools_are_classified_as_public_or_code_execution(self):
        servers = load_server_config(ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json")
        browser = next(server for server in servers if server.server_id == "playwright_browser")
        navigate = _profile_draft(
            browser,
            {
                "name": "browser_navigate",
                "description": "Navigate to a URL.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"url": {}}},
            },
        )
        run_code = _profile_draft(
            browser,
            {
                "name": "browser_run_code_unsafe",
                "description": "Run arbitrary Playwright code.",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {"properties": {"code": {}}},
            },
        )

        self.assertEqual(navigate["sink"], SinkClass.PUBLIC_WEB.value)
        self.assertEqual(navigate["side_effect"], SideEffect.SEND.value)
        self.assertEqual(run_code["sink"], SinkClass.CODE_EXECUTION.value)
        self.assertEqual(run_code["side_effect"], SideEffect.WRITE.value)


if __name__ == "__main__":
    unittest.main()
