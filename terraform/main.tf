

# -------------------------
# VPC
# -------------------------

resource "aws_vpc" "cs2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "cs2-vpc"
  }
}

# -------------------------
# Public subnet
# -------------------------

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.cs2_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "cs2-public-subnet"
  }
}

# -------------------------
# Private subnet
# -------------------------

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.cs2_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-central-1a"

  tags = {
    Name = "cs2-private-subnet"
  }
}

# -------------------------
# Internet Gateway
# -------------------------

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.cs2_vpc.id

  tags = {
    Name = "cs2-igw"
  }
}

# -------------------------
# Public route table
# -------------------------

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.cs2_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "cs2-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# -------------------------
# Private route table
# -------------------------

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.cs2_vpc.id

  tags = {
    Name = "cs2-private-rt"
  }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

# -------------------------
# SOAR Security Group
# -------------------------

resource "aws_security_group" "soar_sg" {
  name        = "cs2-soar-sg"
  description = "Security group for the SOAR server"
  vpc_id      = aws_vpc.cs2_vpc.id

  # Monitoring VM -> SOAR API / metrics
  ingress {
    description = "Allow monitoring network to reach SOAR API"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["192.168.20.0/24"]
  }

  # Allow outbound traffic.
  # This will only work once the private subnet receives an outbound route.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cs2-soar-sg"
  }
}


# -------------------------
# IAM role for SSM
# -------------------------

resource "aws_iam_role" "soar_ssm_role" {
  name = "cs2-soar-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "soar_ssm_policy" {
  role       = aws_iam_role.soar_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "soar_profile" {
  name = "cs2-soar-instance-profile"
  role = aws_iam_role.soar_ssm_role.name
}


# -------------------------
# Find latest Ubuntu AMI
# -------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name = "name"
    values = [
      "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
    ]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


# -------------------------
# SOAR EC2
# -------------------------

resource "aws_instance" "soar" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.soar_sg.id]

  associate_public_ip_address = false

  iam_instance_profile = aws_iam_instance_profile.soar_profile.name

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name = "cs2-soar"
  }
}

resource "aws_security_group" "nat_sg" {
  name        = "cs2-nat-sg"
  description = "Allow private subnet to use NAT instance"
  vpc_id      = aws_vpc.cs2_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.2.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cs2-nat-sg"
  }
}

resource "aws_instance" "nat" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_subnet.id
  associate_public_ip_address = true

  vpc_security_group_ids = [aws_security_group.nat_sg.id]

  source_dest_check = false

    user_data = <<-EOF
#!/bin/bash

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-nat.conf
sysctl --system

INTERFACE=$(ip route | awk '/default/ {print $5; exit}')

iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
iptables -A FORWARD -s 10.0.2.0/24 -j ACCEPT
iptables -A FORWARD -d 10.0.2.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
EOF

  tags = {
    Name = "cs2-nat-instance"
  }
}

resource "aws_route" "private_default_route" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat.primary_network_interface_id
}

# -------------------------
# Customer Gateway
# -------------------------

resource "aws_customer_gateway" "cgw" {
  bgp_asn    = 65000
  ip_address = "145.220.75.5"
  type       = "ipsec.1"

  tags = {
    Name = "cs2-customer-gateway"
  }
}


# -------------------------
# Virtual Private Gateway
# -------------------------

resource "aws_vpn_gateway" "vgw" {
  vpc_id = aws_vpc.cs2_vpc.id

  tags = {
    Name = "cs2-vpn-gateway"
  }
}


# -------------------------
# Site-to-Site VPN
# -------------------------

resource "aws_vpn_connection" "vpn" {
  customer_gateway_id = aws_customer_gateway.cgw.id
  vpn_gateway_id      = aws_vpn_gateway.vgw.id
  type                = "ipsec.1"

  static_routes_only = true

  tags = {
    Name = "cs2-site-to-site-vpn"
  }
}


# -------------------------
# On-premises static routes
# -------------------------

resource "aws_vpn_connection_route" "management" {
  destination_cidr_block = "192.168.10.0/24"
  vpn_connection_id      = aws_vpn_connection.vpn.id
}

resource "aws_vpn_connection_route" "monitoring" {
  destination_cidr_block = "192.168.20.0/24"
  vpn_connection_id      = aws_vpn_connection.vpn.id
}

resource "aws_vpn_connection_route" "cicd" {
  destination_cidr_block = "192.168.30.0/24"
  vpn_connection_id      = aws_vpn_connection.vpn.id
}


# -------------------------
# Route propagation
# -------------------------

resource "aws_vpn_gateway_route_propagation" "private_rt" {
  vpn_gateway_id = aws_vpn_gateway.vgw.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_vpn_gateway_route_propagation" "public_rt" {
  vpn_gateway_id = aws_vpn_gateway.vgw.id
  route_table_id = aws_route_table.public_rt.id
}
