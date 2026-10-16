resource "aws_s3_bucket_acl" "assets" {
  bucket = "example-assets"
  acl    = "public-read"
}
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size = 8
  encrypted = false
}
