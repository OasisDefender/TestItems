import boto3
import os
from dotenv import load_dotenv

# Initialize a session using AWS credentials
load_dotenv("aws.env")
access_key_id = os.environ["AWS_ACCESS_KEY_ID"]
secret_access_key = os.environ["AWS_SECRET_KEY"]
reg_name = os.environ["AWS_REGION_NAME"]

session = boto3.Session(
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key,
    region_name=reg_name  # choose your preferred region
)
ec2 = session.resource('ec2')
elb_client = session.client('elbv2')
rds_client = session.client('rds')
s3_client = session.client('s3')
ec2_client = session.client('ec2')

# Create VPC
vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
vpc.create_tags(Tags=[{"Key": "Name", "Value": "maket1_vpc"}])
vpc.wait_until_available()
elastic_ip = ec2_client.allocate_address(Domain='vpc')
#default_subnet = ec2_client.create_default_subnet(AvailabilityZone='ap-south-1a')

# Create a db subnet group
db_1_subnet = ec2.create_subnet(
    CidrBlock='10.0.10.0/24', VpcId=vpc.id, AvailabilityZone='ap-south-1a')
db_2_subnet = ec2.create_subnet(
    CidrBlock='10.0.11.0/24', VpcId=vpc.id, AvailabilityZone='ap-south-1c')
db_subnet_group = rds_client.create_db_subnet_group(
    DBSubnetGroupName='oazDBSubnetGroup', DBSubnetGroupDescription="oazis test db subnet", SubnetIds=[db_1_subnet.id, db_2_subnet.id])

# Create a security groups
sg_elb_pub = ec2.create_security_group(
    GroupName='sg_elb_pub', Description='LoadBalancer public', VpcId=vpc.id)
sg_elb_priv = ec2.create_security_group(
    GroupName='sg_elb_priv', Description='LoadBalancer private', VpcId=vpc.id)
sg_web_srv_pub = ec2.create_security_group(
    GroupName='sg_web_srv_pub', Description='WWW servers public', VpcId=vpc.id)
sg_web_srv_priv = ec2.create_security_group(
    GroupName='sg_web_srv_priv', Description='WWW servers private', VpcId=vpc.id)
sg_web_cli_priv = ec2.create_security_group(
    GroupName='sg_web_cli_priv', Description='WWW clients private', VpcId=vpc.id)
sg_ssh_srv = ec2.create_security_group(
    GroupName='sg_ssh_srv', Description='SSH servers', VpcId=vpc.id)
sg_ssh_cln = ec2.create_security_group(
    GroupName='sg_ssh_cln', Description='SSH clients', VpcId=vpc.id)
sg_app_srv_pub = ec2.create_security_group(
    GroupName='sg_app_srv_pub', Description='APP servers public', VpcId=vpc.id)
sg_app_srv_priv = ec2.create_security_group(
    GroupName='sg_app_srv_priv', Description='APP servers private', VpcId=vpc.id)
sg_db_srv_pub = ec2.create_security_group(
    GroupName='sg_db_srv_pub', Description='DB servers public', VpcId=vpc.id)
sg_db_srv_priv = ec2.create_security_group(
    GroupName='sg_db_srv_priv', Description='DB servers private', VpcId=vpc.id)

# Add a ruleset
sg_elb_pub.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_elb_pub.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'ToPort': 80, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_pub.id}]},
        {'IpProtocol': 'tcp', 'ToPort': 443, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_pub.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_elb_priv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_elb_priv.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_priv.id}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_priv.id}]}
    ]
)
sg_web_srv_pub.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_web_srv_pub.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 2222, 'ToPort': 2222, 'UserIdGroupPairs': [
            {'Description': 'Public App Servers', 'GroupId': sg_app_srv_pub.id}]}
    ]
)
sg_web_srv_priv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_cli_priv.id}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_cli_priv.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_web_srv_priv.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 2222, 'ToPort': 2222, 'UserIdGroupPairs': [
            {'Description': 'Private App Servers', 'GroupId': sg_app_srv_priv.id}]}
    ]
)
sg_web_cli_priv.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_priv.id}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'UserIdGroupPairs': [
            {'Description': 'Private Web clients', 'GroupId': sg_web_srv_priv.id}]}
    ]
)
sg_web_cli_priv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_ssh_srv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_ssh_cln.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_ssh_cln.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_app_srv_pub.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 2222, 'ToPort': 2222, 'UserIdGroupPairs': [
            {'Description': 'Public Web Servers', 'GroupId': sg_web_srv_pub.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_app_srv_pub.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'UserIdGroupPairs': [
            {'Description': 'Public MYSQL', 'GroupId': sg_db_srv_pub.id}]}
    ]
)
sg_app_srv_priv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 2222, 'ToPort': 2222, 'UserIdGroupPairs': [
            {'Description': 'Private Web Servers', 'GroupId': sg_web_srv_priv.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_app_srv_priv.authorize_egress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'UserIdGroupPairs': [
            {'Description': 'Private MYSQL', 'GroupId': sg_db_srv_priv.id}]}
    ]
)
sg_db_srv_pub.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'UserIdGroupPairs': [
            {'Description': 'Public App Servers', 'GroupId': sg_app_srv_pub.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)
sg_db_srv_priv.authorize_ingress(
    IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'UserIdGroupPairs': [
            {'Description': 'Private App Servers', 'GroupId': sg_app_srv_pub.id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -
            1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ]
)

# Create Internet Gateway and attach to VPC
internet_gateway = ec2_client.create_internet_gateway()
vpc.attach_internet_gateway(
    InternetGatewayId=internet_gateway['InternetGateway']['InternetGatewayId'])

# Create a route table and a public route
route_table = vpc.create_route_table()
route = route_table.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=internet_gateway['InternetGateway']['InternetGatewayId']
)

# Create a public subnet
public_subnet = ec2.create_subnet(
    CidrBlock='10.0.1.0/24', VpcId=vpc.id, AvailabilityZone='ap-south-1a')
route_table.associate_with_subnet(SubnetId=public_subnet.id)
# Create a private subnet
private_subnet = ec2.create_subnet(
    CidrBlock='10.0.2.0/24', VpcId=vpc.id, AvailabilityZone='ap-south-1a')
# Create a clients subnet
clients_subnet = ec2.create_subnet(
    CidrBlock='10.0.3.0/24', VpcId=vpc.id, AvailabilityZone='ap-south-1a')

# 1. Create a NAT Gateway and attach it to the VPC
nat_eip = ec2_client.allocate_address(Domain='vpc')
nat_gateway = ec2_client.create_nat_gateway(
    SubnetId=public_subnet.id,
    AllocationId=elastic_ip['AllocationId']
)

# 2. Create EC2 instances (Web servers)
instances_pub = ec2.create_instances(
    ImageId='ami-0d13e3e640877b0b9',
    MinCount=3,
    MaxCount=3,
    InstanceType='t2.micro',
    # KeyName='keypair_web_srv_pub',
    SubnetId=public_subnet.id,
    # Placement={'AvailabilityZone': 'ap-south-1a'},
    SecurityGroupIds=[sg_web_srv_pub.id, sg_ssh_srv.id],
)
instances_priv = ec2.create_instances(
    ImageId='ami-0d13e3e640877b0b9',
    MinCount=3,
    MaxCount=3,
    InstanceType='t2.micro',
    # KeyName='keypair_web_srv_priv',
    SubnetId=private_subnet.id,
    # Placement={'AvailabilityZone': 'ap-south-1a'},
    SecurityGroupIds=[sg_web_srv_priv.id, sg_ssh_srv.id],
)

# 3. Create 2 Elastic Load Balancers
# 1
elb_pub = elb_client.create_load_balancer(
    Name='oazPublicLoadBalancer',
    Subnets=[
        public_subnet.id,
    ],
    # SecurityGroups=[
    #    sg_elb_pub.id,
    # ],
    Scheme='internet-facing',
    Type='network'
)
# 2
elb_priv = elb_client.create_load_balancer(
    Name='oazPrivateLoadBalancer',
    Subnets=[
        private_subnet.id,
    ],
    # SecurityGroups=[
    #    sg_elb_pub.id,
    # ],
    Scheme='internal',
    Type='network'
)

# 4. Register instances with the load balancers
grp_pub = elb_client.create_target_group(
    Name='pub-targets',
    Port=443,
    Protocol='TCP',
    VpcId=vpc.id,
)
grp_priv = elb_client.create_target_group(
    Name='priv-targets',
    Port=443,
    Protocol='TCP',
    VpcId=vpc.id,
)

for group in grp_pub['TargetGroups']:
    if (group['TargetGroupName'] == 'pub-targets'):
        pub_arn = group['TargetGroupArn']
for instance in instances_pub:
    elb_client.register_targets(
        TargetGroupArn=pub_arn,
        Targets=[{'Id': instance.instance_id}]
    )
for group in grp_priv['TargetGroups']:
    if (group['TargetGroupName'] == 'priv-targets'):
        priv_arn = group['TargetGroupArn']
for instance in instances_priv:
    elb_client.register_targets(
        TargetGroupArn=priv_arn,
        Targets=[{'Id': instance.instance_id}]
    )
response1 = elb_client.create_listener(
    DefaultActions=[
        {
            'TargetGroupArn': pub_arn,
            'Type': 'forward',
        },
    ],
    # 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188',
    LoadBalancerArn=elb_pub['LoadBalancers'][0]['LoadBalancerArn'],
    Port=443,
    Protocol='TCP',
)
response2 = elb_client.create_listener(
    DefaultActions=[
        {
            'TargetGroupArn': priv_arn,
            'Type': 'forward',
        },
    ],
    # 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188',
    LoadBalancerArn=elb_priv['LoadBalancers'][0]['LoadBalancerArn'],
    Port=443,
    Protocol='TCP',
)

# 5. Create RDS instance
rds_pub = rds_client.create_db_instance(
    DBName='Database_pub',
    AllocatedStorage=20,
    DBInstanceIdentifier='oaz-dbinstance-pub',
    Engine='mysql',
    MasterUsername='username',
    MasterUserPassword='password',
    VpcSecurityGroupIds=[sg_db_srv_pub.id],
    DBInstanceClass='db.t2.micro',
    PubliclyAccessible=False,
    # AvailabilityZone='ap-south-1'
    DBSubnetGroupName=db_subnet_group['DBSubnetGroup']['DBSubnetGroupName']
)
rds_priv = rds_client.create_db_instance(
    DBName='Database_priv',
    AllocatedStorage=20,
    DBInstanceIdentifier='oaz-dbinstance-priv',
    Engine='mysql',
    MasterUsername='username',
    MasterUserPassword='password',
    VpcSecurityGroupIds=[sg_db_srv_priv.id],
    DBInstanceClass='db.t2.micro',
    PubliclyAccessible=False,
    # AvailabilityZone='ap-south-1'
    DBSubnetGroupName=db_subnet_group['DBSubnetGroup']['DBSubnetGroupName']
)

# 6. Create EC2 instances (Clients)
instances_cli = ec2.create_instances(
    ImageId='ami-0d13e3e640877b0b9',
    MinCount=3,
    MaxCount=3,
    InstanceType='t2.micro',
    # KeyName='keypair_web_cli_priv',  #  XXX replace with your key-pair name
    SubnetId=clients_subnet.id,
    #Placement={'AvailabilityZone': 'ap-south-1a'},
    SecurityGroupIds=[sg_web_cli_priv.id, sg_ssh_srv.id, sg_ssh_cln.id],
)

# 7. Create EC2 instances (App Servers)
instances_app_pub = ec2.create_instances(
    ImageId='ami-0d13e3e640877b0b9',
    MinCount=1,
    MaxCount=1,
    InstanceType='t2.micro',
    # KeyName='keypair_app_srv_pub',
    SubnetId=public_subnet.id,
    #Placement={'AvailabilityZone': 'ap-south-1a'},
    SecurityGroupIds=[sg_app_srv_pub.id, sg_ssh_srv.id],
)
instances_app_priv = ec2.create_instances(
    ImageId='ami-0d13e3e640877b0b9',
    MinCount=1,
    MaxCount=1,
    InstanceType='t2.micro',
    # KeyName='keypair_app_srv_priv',
    SubnetId=private_subnet.id,
    #Placement={'AvailabilityZone': 'ap-south-1a'},
    SecurityGroupIds=[sg_app_srv_priv.id, sg_ssh_srv.id],
)

# 8. Create S3 bucket
s3_client.create_bucket(Bucket='oazbucketawstest', CreateBucketConfiguration={
                        'LocationConstraint': 'ap-south-1'})

# Wait for NAT gateway to be available
#waiter = ec2_client.get_waiter('nat_gateway_available')
# waiter.wait(NatGatewayIds=[nat_gateway['NatGateway']['NatGatewayId']])
