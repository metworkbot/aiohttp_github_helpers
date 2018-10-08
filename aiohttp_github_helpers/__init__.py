import logging
import hmac
import fnmatch
from aiohttp import web

LOGGER = logging.getLogger("aiohttp_github_helpers")
GITHUB_CHECK_SIGNATURE_SECRET = b'CHANGEME'
GITHUB_ROOT = "https://api.github.com"


@web.middleware
async def github_check_signature(request, handler):
    """Check the GitHub signature or return an HTTP/400.

    This is an aiohttp middleware. We check the GitHub hook signature
    (see corresponding doc at github on hook secrets). The secret must be
    available in GITHUB_CHECK_SIGNATURE_SECRET global variable.

    Args:
        request: aiohttp.web.Request object corresponding to the incoming
            http request from the client.
        handler: aiohttp handler (see middlewares documentation).

    Returns:
        aiohttp Response (see middlewares documentation).

    """
    if 'X-Hub-Signature' not in request.headers:
        return web.Response(status=400, body=b"no X-Hub-Signature header")
    x_hub_signature = request.headers.get('X-Hub-Signature')
    body = await request.read()
    sign = hmac.new(GITHUB_CHECK_SIGNATURE_SECRET, body, 'sha1')
    signature = "sha1=" + sign.hexdigest()
    if signature != x_hub_signature:
        return web.Response(status=400, body=b"bad signature")
    return handler(request)


@web.middleware
async def github_check_github_event(request, handler):
    """Check the GitHub event or return an HTTP/400.

    This is an aiohttp middleware. If we can't get the X-GitHub-Event in
    request headers, we return an HTTP/400 error. Else, the value is stored
    in the request object dict in the key 'github_event'.

    Args:
        request: aiohttp.web.Request object corresponding to the incoming
            http request from the client.
        handler: aiohttp handler (see middlewares documentation).

    Returns:
        aiohttp Response (see middlewares documentation).

    """
    if 'X-GitHub-Event' not in request.headers:
        return web.Response(status=400, body=b"no X-GitHub-Event header")
    request['github_event'] = request.headers.get('X-GitHub-Event')
    return handler(request)


async def github_add_labels_on_issue(client_session, owner, repo, issue_number,
                                     labels_to_add):
    """
    Add somes labels to a github issue.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.
        labels_to_add (list): list of strings to add as labels.

    Returns:
        boolean: True if it's ok, False else

    """
    if len(labels_to_add) == 0:
        return True
    url = "%s/repos/%s/%s/issues/%i/labels" % (GITHUB_ROOT, owner, repo,
                                               issue_number)
    LOGGER.info("creating labels: %s on %s..." % (labels_to_add, url))
    async with client_session.post(url, json=labels_to_add) as r:
        if r.status != 200:
            LOGGER.warning("can't create labels: %s on %s (status: %i)" %
                           (labels_to_add, url, r.status))
            return False
        try:
            await r.json()
        except Exception as e:
            LOGGER.warning("can't create labels: %s on %s "
                           "(exception: %s)" % (labels_to_add, url, e))
            return False


async def github_get_labels_on_issue(client_session, owner, repo,
                                     issue_number):
    """
    Get the list of labels of a github issue.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.

    Returns:
        list: list of labels (as strings) or None (if problems).

    """
    url = "%s/repos/%s/%s/issues/%i/labels" % (GITHUB_ROOT, owner, repo,
                                               issue_number)
    LOGGER.debug("getting labels on %s..." % url)
    async with client_session.get(url) as r:
        if r.status != 200:
            LOGGER.warning("can't get labels on %s (status: %i)" %
                           (url, r.status))
            return None
        try:
            result = await r.json()
        except Exception as e:
            LOGGER.warning("can't get labels on %s "
                           "(exception: %s)" % (url, e))
            return None
        return [x['name'] for x in result]


async def github_delete_label_on_issue(client_session, owner, repo,
                                       issue_number, label):
    """
    Delete a label from a github issue.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.
        label (string): label string to delete

    Returns:
        boolean: True if ok, False else

    """
    url = "%s/repos/%s/%s/issues/%i/labels/%s" % (GITHUB_ROOT, owner, repo,
                                                  issue_number, label)
    LOGGER.info("deleting label: %s on %s..." % (label, url))
    async with client_session.delete(url) as r:
        if r.status != 200:
            LOGGER.warning("can't delete label: %s on %s (status: %i)" %
                           (label, url, r.status))
            return False
        try:
            await r.json()
        except Exception as e:
            LOGGER.warning("can't delete label: %s on %s "
                           "(exception: %s)" % (label, url, e))
            return False


async def github_delete_labels_on_issue_with_globs(client_session, owner, repo,
                                                   issue_number, glob_include,
                                                   glob_exclude=""):
    """
    Delete some labels from a github issue with globs (see fnmatch module).

    To be deleted a label must match to the glob_include pattern AND NOT match
    to the glob_exclude pattern.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.
        glob_include (string): glob string (as defined in fnmatch module) to
            select which labels to delete.
        glob_exclude (string): glob string (as defined in fnmatch module) to
            select which labels NOT to delete.

    Returns:
        (list, list): tuple of lists. The first element is the list of
            remaining labels (or None if problems), Second element is the
            original list of labels (or None if problems).

    """
    labels = await github_get_labels_on_issue(client_session, owner, repo,
                                              issue_number)
    if labels is None:
        return (None, None)
    new_labels = []
    for label in labels:
        if fnmatch.fnmatch(label, glob_include) and \
                not fnmatch.fnmatch(label, glob_exclude):
            res = await github_delete_label_on_issue(client_session, owner,
                                                     repo, issue_number,
                                                     label)
            if res is not True:
                new_labels.append(label)
        else:
            new_labels.append(label)
    return (new_labels, labels)


async def github_conditional_add_label_on_issue(client_session, owner, repo,
                                                issue_number, label_to_add,
                                                glob_not_to_match):
    """
    Add label to a github issue if none on current labels match the given glob.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.
        lable_to_add (string): the label to add.
        glob_not_to_match (string): glob string (as defined in fnmatch module)
            to test with every current labels on the issue.

    Returns:
        boolean: True if the label was added, False else.

    """
    labels = await github_get_labels_on_issue(client_session, owner, repo,
                                              issue_number)
    if labels is None:
        return False
    add_label = not any([fnmatch.fnmatch(x, glob_not_to_match)
                         for x in labels])
    if add_label is False:
        return False
    return await github_add_labels_on_issue(client_session, owner, repo,
                                            issue_number, label_to_add)


async def github_replace_labels_with(client_session, owner, repo, issue_number,
                                     glob_to_remove, new_label,
                                     always_add=False):
    """
    Replace some labels from a github issue matching with a glob by a new one.

    Note: if the new_label to add is already present, it is not removed then
    added another time.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): number of the issue at github.
        glob_to_remove (string): glob string (as defined in fnmatch module) to
            select which labels to delete.
        new_label (string): new label to add.
        always_add (boolean): True if you want to add the new_label even
            if no label was removed.

    Returns:
        boolean: True if new_label was added (or was already here),
            False else, None if problems.

    """
    remaining_labels, original_labels = \
        await github_delete_labels_on_issue_with_globs(client_session,
                                                       owner, repo,
                                                       issue_number,
                                                       glob_to_remove,
                                                       new_label)
    if remaining_labels is None or original_labels is None:
        return None
    if (not always_add) and (len(remaining_labels) == len(original_labels)):
        return False
    if new_label in remaining_labels:
        return True
    return await github_add_labels_on_issue(client_session, owner, repo,
                                            issue_number, [new_label])


async def github_create_status(client_session, owner, repo, sha, status_state,
                               status_target_url, status_description,
                               status_context):
    """
    Create a status for the given sha.

    see https://developer.github.com/v3/repos/statuses/#create-a-status

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        sha (string): the sha of the commit.
        status_state (string): the state of the status (error, failure, pending
            or success).
        status_target_url: status target url (see github doc).
        status_description: status description (see github doc).
        status_context: status context (see github doc).

    Returns:
        boolean: True if the status was created, False else.

    """
    posted_body = {
        "state": status_state,
        "target_url": status_target_url,
        "description": status_description,
        "context": status_context
    }
    url = "%s/repos/%s/%s/statuses/%s" % (GITHUB_ROOT, owner, repo, sha)
    LOGGER.info("creating status %s (context: %s) for url: %s" %
                (status_state, status_context, url))
    async with client_session.post(url, json=posted_body) as r:
        if r.status != 200:
            LOGGER.warning("can't create status %s (context: %s) "
                           "for url: %s" % (status_state, status_context, url))
            return False
        try:
            await r.json()
        except Exception:
            LOGGER.warning("can't create status %s (context: %s) "
                           "for url: %s" % (status_state, status_context, url))
            return False
    return True


async def github_post_comment(client_session, owner, repo, issue_number,
                              comment_body):
    """
    Post a comment to a github issue.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        issue_number (int): the issue number.
        comment_body (string): the body of the comment.

    Returns:
        boolean: True if the comment was created, False else.

    """
    posted_body = {"body": comment_body}
    url = "%s/repos/%s/%s/issues/%i/comments" % (GITHUB_ROOT, owner, repo,
                                                 issue_number)
    LOGGER.info("posting comment to %s..." % url)
    async with client_session.post(url, json=posted_body) as r:
        if r.status != 200:
            LOGGER.warning("can't create comment on %s" % url)
            return False
        try:
            await r.json()
        except Exception:
            LOGGER.warning("can't create comment on %s" % url)
            return False
    return True


async def github_get_pr_commit_messages_list(client_session, owner, repo,
                                             pr_number):
    """
    Get the list of commit messages for a given pull-request.

    Params:
        client_session: aiohttp ClientSession.
        owner: owner of the repository at github.
        repo: repository name at github (without owner part).
        pr_number (int): the pull-request number.

    Returns:
        list: list of commit messages (of the PR) as strings (or None if
            problems)

    """
    url = "%s/repos/%s/%s/pulls/%i/commits" % (GITHUB_ROOT, owner, repo,
                                               pr_number)
    async with client_session.get(url) as r:
        if r.status != 200:
            LOGGER.warning("can't get commits list on %s" % url)
            return None
        try:
            reply = await r.json()
        except Exception:
            LOGGER.warning("can't get commits list on %s" % url)
            return None
    return [x['commit']['message'] for x in reply]
