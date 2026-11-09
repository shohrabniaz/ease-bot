# Seeded misconfigurations for the EASE-Bot demo. Do not deploy.
resource "aws_s3_bucket" "reports" {
  bucket = "ease-bot-demo-reports"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = aws_s3_bucket.reports.id
  acl    = "public-read"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "ap-southeast-2a"
  size              = 20
  encrypted         = false
}

resource "aws_security_group" "ssh" {
  name        = "demo-ssh"
  description = "SSH access"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
