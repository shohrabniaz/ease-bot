from easebot.suggest import commentable_hunks, split_postable, suggestions, unified


def test_replacement_suggestion():
    s = suggestions("a\nb\nc\n", "a\nB\nc\n")
    assert [(x.start, x.end, x.replacement) for x in s] == [(2, 2, ["B"])]
    assert s[0].body() == "```suggestion\nB\n```"


def test_insertion_is_anchored_on_previous_line():
    s = suggestions("a\nb\n", "a\nnew\nb\n")
    assert [(x.start, x.end, x.replacement) for x in s] == [(1, 1, ["a", "new"])]


def test_insertion_at_top_anchors_on_first_line():
    s = suggestions("a\n", "top\na\n")
    assert [(x.start, x.end, x.replacement) for x in s] == [(1, 1, ["top", "a"])]


def test_deletion_gives_empty_suggestion():
    s = suggestions("a\nb\nc\n", "a\nc\n")
    assert [(x.start, x.end, x.replacement) for x in s] == [(2, 2, [])]


def test_nearby_edits_are_merged():
    s = suggestions("1\n2\n3\n4\n5\n", "X\n2\nY\n4\n5\n")
    assert len(s) == 1 and (s[0].start, s[0].end) == (1, 3)


def test_far_edits_stay_separate():
    orig = "".join(f"{i}\n" for i in range(20))
    fixed = orig.replace("1\n", "one\n", 1).replace("18\n", "eighteen\n")
    assert len(suggestions(orig, fixed)) == 2


def test_fence_escalates_when_content_has_backticks():
    s = suggestions("a\n", "```\n")
    assert s[0].body().startswith("````suggestion")


PATCH = "@@ -1,2 +1,3 @@\n a\n-b\n+B\n+c\n@@ -10,2 +11,2 @@\n x\n+y\n"


def test_commentable_hunks():
    assert commentable_hunks(PATCH) == [{1, 2, 3}, {11, 12}]
    assert commentable_hunks(None) == []


def test_split_postable_requires_whole_range_in_one_hunk():
    sugs = suggestions("a\nB\nc\n" + "z\n" * 20, "A\nB\nC\n" + "z\n" * 20)
    post, other = split_postable(sugs, PATCH)
    assert len(post) == 1 and not other
    post, other = split_postable(sugs, "@@ -1,1 +1,1 @@\n+a\n")
    assert not post and len(other) == 1


def test_unified_diff():
    d = unified("a\n", "b\n", "x.tf")
    assert "--- a/x.tf" in d and "-a" in d and "+b" in d
