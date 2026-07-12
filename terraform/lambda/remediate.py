"""Auto-remediation: re-applies the S3 public access block when drift is detected.
Finding -> fix in seconds. HIPAA 164.312(b) / NIST SI-4 continuous monitoring."""
import boto3

s3 = boto3.client("s3")

def handler(event, context):
    detail = event.get("detail", {})
    bucket = (detail.get("requestParameters") or {}).get("bucketName")
    if not bucket:
        return {"status": "skipped", "reason": "no bucket in event"}

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print(f"REMEDIATED: re-applied public access block on {bucket}")
    return {"status": "remediated", "bucket": bucket}