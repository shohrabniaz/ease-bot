import pytest

from easebot.validate import intent_check, syntax_check, tf_identities

TF = '''resource "aws_s3_bucket" "logs" {
  bucket = "x"
}
data "aws_iam_policy_document" "p" {}
module "vpc" {
  source = "./vpc"
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

K8S = '''apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
    - name: web
      image: nginx:1.27
      ports:
        - containerPort: 8080
'''


def test_tf_identities():
    assert tf_identities(TF) == {"aws_s3_bucket.logs", "data.aws_iam_policy_document.p", "module.vpc",
                                 "aws_security_group.ssh"}


def test_tf_rename_is_rejected():
    ok, msg, _ = intent_check(TF, TF.replace('"logs"', '"logs2"'), "terraform")
    assert not ok and "aws_s3_bucket.logs" in msg


def test_tf_addition_is_allowed_and_reported():
    ok, msg, added = intent_check(TF, TF + 'resource "aws_s3_bucket_public_access_block" "logs" {\n  bucket = "x"\n}\n',
                                  "terraform")
    assert ok and added == ["aws_s3_bucket_public_access_block.logs"]


def test_tf_deleting_ingress_block_is_rejected():
    start = TF.index("  ingress {")
    end = TF.index("  }\n", start) + 4
    ok, msg, _ = intent_check(TF, TF[:start] + TF[end:], "terraform")
    assert not ok and "ingress" in msg


def test_tf_restricting_ingress_is_allowed():
    ok, _, _ = intent_check(TF, TF.replace("0.0.0.0/0", "10.0.0.0/8"), "terraform")
    assert ok


def test_k8s_image_swap_is_rejected():
    ok, msg, _ = intent_check(K8S, K8S.replace("nginx:1.27", "nginx@sha256:deadbeef"), "kubernetes")
    assert not ok and "nginx:1.27" in msg


def test_k8s_port_removal_is_rejected():
    fixed = K8S.replace("      ports:\n        - containerPort: 8080\n", "")
    ok, msg, _ = intent_check(K8S, fixed, "kubernetes")
    assert not ok and "port:8080" in msg


def test_k8s_security_context_addition_is_fine():
    fixed = K8S + "      securityContext:\n        runAsNonRoot: true\n"
    assert intent_check(K8S, fixed, "kubernetes")[0]


@pytest.mark.parametrize("text,expected", [(K8S, None), ("kind: [\n", False), ("just: text\n", False)])
def test_k8s_syntax_without_tools(text, expected):
    ok, _ = syntax_check(text, "kubernetes", use_tools=False)
    assert ok is expected


def test_tf_syntax_without_tools_is_unchecked_not_passed():
    ok, msg = syntax_check(TF, "terraform", use_tools=False)
    assert ok is None and "brace" in msg
    assert syntax_check(TF + "{", "terraform", use_tools=False)[0] is False
