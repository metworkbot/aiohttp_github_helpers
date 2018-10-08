from aiohttp import ClientSession
import pytest
import pytest_asyncio.plugin

import aiohttp_github_helpers as h

TEST_OWNER = "metwork-framework"
TEST_REPO = "testrepo"


@pytest.mark.asyncio
async def test_github_get_labels_on_issue():
    async with ClientSession() as client_session:
        labels = await h.github_get_labels_on_issue(client_session, TEST_OWNER,
                                                    TEST_REPO, 38)
        assert len(labels) == 2
        assert sorted(labels)[0] == 'Status: Closed'
        assert sorted(labels)[1] == 'Type: Mixed'


@pytest.mark.asyncio
async def test_github_get_pr_commit_messages_list():
    async with ClientSession() as client_session:
        messages = await h.github_get_pr_commit_messages_list(client_session,
                                                              TEST_OWNER,
                                                              TEST_REPO,
                                                              58)
        assert len(messages) == 1
        assert messages[0] == 'Update README.md'
