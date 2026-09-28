#!/usr/bin/env python3
# kiro-classification: public
"""Set up S3 Files infrastructure for persistent workspaces.

Creates: file system, mount targets, security group, and access point.
Outputs the CDK context values needed for deployment.

Usage:
    python scripts/setup-s3files.py --region us-east-1
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import boto3


def main() -> None:
    parser = argparse.ArgumentParser(description="Set up S3 Files for persistent workspaces")
    parser.add_argument("--region", required=True, help="AWS region")
    args = parser.parse_args()

    region = args.region
    s3files = boto3.client("s3files", region_name=region)
    cf = boto3.client("cloudformation", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    # 1. Find the artifact bucket from StateStack
    print("Finding StateStack artifact bucket...")
    try:
        outputs = cf.describe_stacks(StackName="StateStack")["Stacks"][0]["Outputs"]
    except Exception:
        print("ERROR: StateStack not found. Run `npx cdk deploy StateStack` first.", file=sys.stderr)
        sys.exit(1)

    bucket_arn = None
    for out in outputs:
        val = out["OutputValue"]
        if val.startswith("arn:aws:s3:::"):
            bucket_arn = val
            break
        elif val.startswith("statestack-") and "artifact" in val.lower():
            bucket_arn = f"arn:aws:s3:::{val}"
            break

    if not bucket_arn:
        print("ERROR: Could not find artifact bucket in StateStack outputs.", file=sys.stderr)
        sys.exit(1)
    bucket_name = bucket_arn.replace("arn:aws:s3:::", "")
    print(f"  Bucket: {bucket_arn}")
    print("Enabling S3 bucket versioning...")
    s3c = boto3.client("s3", region_name=region)
    try:
        s3c.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"})
        print("  Versioning enabled")
    except Exception as ve:
        print(f"  Versioning: {ve}")

    # 2. Find the VPC and subnets from NetworkStack
    print("Finding NetworkStack VPC and subnets...")
    try:
        net_outputs = cf.describe_stacks(StackName="NetworkStack")["Stacks"][0]["Outputs"]
    except Exception:
        print("ERROR: NetworkStack not found. Run `npx cdk deploy NetworkStack` first.", file=sys.stderr)
        sys.exit(1)

    vpc_id = None
    proxy_subnets = []
    connector_sg = None
    for out in net_outputs:
        key = out.get("OutputKey", "")
        val = out["OutputValue"]
        if "Egress" in key and val.startswith("vpc-"):
            vpc_id = val
        if "proxySubnet" in key.lower() or "EgressproxySubnet" in key:
            proxy_subnets.append(val)
        if "ProxyFleet" in key and "GroupId" in key:
            # Connector SG for NFS ingress rule
            pass  # We'll create our own SG

    if not vpc_id:
        print("ERROR: Could not find VPC in NetworkStack outputs.", file=sys.stderr)
        sys.exit(1)

    # Get proxy subnets from outputs
    for out in net_outputs:
        key = out.get("OutputKey", "")
        val = out["OutputValue"]
        if "proxySubnet" in key and val.startswith("subnet-"):
            if val not in proxy_subnets:
                proxy_subnets.append(val)
        elif "Subnet" in key and val.startswith("subnet-"):
            if val not in proxy_subnets:
                proxy_subnets.append(val)

    if not proxy_subnets:
        print("ERROR: Could not find subnets in NetworkStack outputs.", file=sys.stderr)
        sys.exit(1)
    print(f"  VPC: {vpc_id}")
    print(f"  Subnets: {proxy_subnets}")

    # 3. Find or create the connector security group (for NFS ingress)
    print("Finding connector security group...")
    # The connector SG is the one the MicroVMs use
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["*connector*", "*Connector*"]}]
    )["SecurityGroups"]
    if not sgs:
        # Try broader search
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
    connector_sg_id = sgs[0]["GroupId"] if sgs else None
    print(f"  Connector SG: {connector_sg_id or '(not found, using VPC default)'}")

    # 4. Create NFS security group
    print("Creating NFS mount target security group...")
    try:
        sg_resp = ec2.create_security_group(
            GroupName=f"s3files-mount-targets-{int(time.time())}",
            Description="Allow NFS 2049 from connector SG for S3 Files",
            VpcId=vpc_id,
        )
        mt_sg_id = sg_resp["GroupId"]
        # Allow NFS from any source in the VPC (the connector SG may change)
        ec2.authorize_security_group_ingress(
            GroupId=mt_sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 2049,
                "ToPort": 2049,
                "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "NFS from VPC"}],
            }],
        )
        print(f"  Created SG: {mt_sg_id}")
    except Exception as e:
        print(f"  SG creation failed: {e}. Using first VPC SG.")
        mt_sg_id = connector_sg_id or sgs[0]["GroupId"]

    # 5. Create S3 Files service role
    print("Creating S3 Files service role...")
    iam = boto3.client("iam")
    role_name = "S3FilesServiceRole"
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticfilesystem.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            }),
            Description="S3 Files sync role",
        )
            # WARNING: AmazonS3FullAccess is overly broad for production.
            # Replace with a scoped policy granting only s3:GetObject, s3:PutObject,
            # s3:DeleteObject, s3:ListBucket on the specific artifact bucket ARN.
        iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
        print(f"  Created role: {role_name}")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"  Role exists: {role_name}")
    try:
        att = iam.list_attached_role_policies(RoleName=role_name)
        arns = [p["PolicyArn"] for p in att.get("AttachedPolicies", [])]
        if "arn:aws:iam::aws:policy/AmazonS3FullAccess" not in arns:
            # WARNING: AmazonS3FullAccess is overly broad for production.
            # Replace with a scoped policy granting only s3:GetObject, s3:PutObject,
            # s3:DeleteObject, s3:ListBucket on the specific artifact bucket ARN.
            iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
            print(f"  Attached AmazonS3FullAccess")
        else:
            print("  Policy already attached")
    except Exception as pe:
        print(f"  WARNING: policy check: {pe}")

    account = boto3.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    # 6. Create file system
    print("Creating S3 Files file system...")
    try:
        fs = s3files.create_file_system(
            bucket=bucket_arn,
            prefix="workspaces/",
            roleArn=role_arn,
            acceptBucketWarning=True,
        )
        fs_id = fs["fileSystemId"]
        print(f"  File system: {fs_id}")
    except Exception as e:
        if "already exists" in str(e).lower() or "FileSystemAlreadyExists" in str(e):
            # List existing
            existing = s3files.list_file_systems()
            fs_id = existing["fileSystems"][0]["fileSystemId"]
            print(f"  Existing file system: {fs_id}")
        else:
            raise

    # Wait for filesystem to be available
    print("  Waiting for file system...")
    for _attempt in range(24):  # 2 min max
        try:
            fs_info = s3files.get_file_system(fileSystemId=fs_id)
            if fs_info.get("status") == "available":
                break
        except Exception:  # nosec B110 — idempotent setup; pre-existing resources are expected
            pass
        time.sleep(5)  # nosemgrep: arbitrary-sleep — polling loop by design  # nosemgrep: arbitrary-sleep

    # 7. Create mount targets
    print("Creating mount targets...")
    mt_ips = []
    for subnet_id in proxy_subnets[:2]:  # One per AZ, max 2
        try:
            mt = s3files.create_mount_target(
                fileSystemId=fs_id,
                subnetId=subnet_id,
                securityGroups=[mt_sg_id],
            )
            mt_id = mt["mountTargetId"]
            # Wait and get IP
            for _ in range(20):
                info = s3files.get_mount_target(mountTargetId=mt_id)
                ip = info.get("ipv4Address", "")
                if ip:
                    mt_ips.append(ip)
                    print(f"  {mt_id}: {ip} in {subnet_id}")
                    break
                time.sleep(3)  # nosemgrep: arbitrary-sleep — polling loop by design
        except Exception as e:
            if "already exists" in str(e).lower():
                # Get existing
                existing = s3files.list_mount_targets(fileSystemId=fs_id)
                for emt in existing.get("mountTargets", []):
                    info = s3files.get_mount_target(mountTargetId=emt["mountTargetId"])
                    ip = info.get("ipv4Address", "")
                    if ip and ip not in mt_ips:
                        mt_ips.append(ip)
                        print(f"  {emt['mountTargetId']}: {ip} (existing)")
                break
            else:
                print(f"  Mount target failed: {e}")

    # 8. Create access point
    print("Creating default access point...")
    try:
        ap = s3files.create_access_point(
            fileSystemId=fs_id,
            rootDirectory={"path": "/"},
            posixUser={"uid": 0, "gid": 0},
        )
        ap_id = ap["accessPointId"]
        print(f"  Access point: {ap_id}")
    except Exception as e:
        if "already exists" in str(e).lower():
            existing = s3files.list_access_points(fileSystemId=fs_id)
            ap_id = existing["accessPoints"][0]["accessPointId"]
            print(f"  Existing access point: {ap_id}")
        else:
            raise

    if connector_sg_id and mt_sg_id:
        print("Adding NFS egress rule to connector SG...")
        try:
            ec2.authorize_security_group_egress(GroupId=connector_sg_id, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049, "UserIdGroupPairs": [{"GroupId": mt_sg_id}]}])
            print(f"  Added egress rule")
        except Exception as se:
            if "Duplicate" in str(se) or "already" in str(se).lower():
                print("  Egress rule exists")
            else:
                print(f"  WARNING: {se}")

    # Output
    mt_ips_str = ",".join(mt_ips)
    print("\n" + "=" * 60)
    print("S3 Files infrastructure created.")
    print("Re-deploy with:")
    print(f"  npx cdk deploy --all \\")
    print(f"    -c imageVersion=<version> \\")
    print(f"    -c proxyImageUri=<uri> \\")
    print(f"    -c s3filesFilesystemId={fs_id} \\")
    print(f"    -c s3filesAccessPointId={ap_id} \\")
    print(f"    -c s3filesMountTargetIps={mt_ips_str}")
    print("=" * 60)


if __name__ == "__main__":
    main()
