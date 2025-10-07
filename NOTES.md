# Notes – Module #19: SIEM Setup with Wazuh

# 🗒️ Wazuh & Stratus Red Team - Technical Reference

## 📌 Core Components

### Wazuh
- **Version**: 4.7.0+
- **Components**: Manager, API, Dashboard
- **Key Features**:
  - Real-time threat detection
  - Log analysis and correlation
  - File integrity monitoring
  - Vulnerability detection
  - Configuration assessment

### Stratus Red Team
- **Version**: Latest
- **Purpose**: Cloud-native attack emulation
- **Key Capabilities**:
  - Simulates real-world attack techniques
  - Tests detection capabilities
  - Validates security controls
  - Supports MITRE ATT&CK framework

## 🛠️ Local Development Setup

### Prerequisites
- Python 3.8+
- Go 1.17+ (for Stratus Red Team)
- Terraform 1.0+ (for infrastructure as code)
- Docker & Docker Compose (for local testing)

### Environment Variables
```bash
# AWS Configuration
export AWS_REGION=us-east-1
export AWS_PROFILE=sandbox-account

# Wazuh Configuration
export WAZUH_MANAGER=wazuh-manager.local
export WAZUH_API_USER=wazuh-user
export WAZUH_API_PASSWORD=your-secure-password
```

## 🔍 Wazuh Commands

### Service Management
```bash
# Check Wazuh status
sudo systemctl status wazuh-manager

# Restart Wazuh
sudo systemctl restart wazuh-manager

# View logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Rule Management
```bash
# List all rules
/var/ossec/bin/agent_control -l

# Test rule matching
/var/ossec/bin/wazuh-logtest

# Update rules
/var/ossec/bin/update_rule_files.py -a
```

## ☁️ AWS Commands

### IAM & Security
```bash
# Get current IAM identity
aws sts get-caller-identity

# List IAM roles
aws iam list-roles

# Check CloudTrail status
aws cloudtrail describe-trails
```

### EC2 & VPC
```bash
# List EC2 instances
aws ec2 describe-instances

# Check security groups
aws ec2 describe-security-groups

# View VPC flow logs
aws ec2 describe-flow-logs
```

## 🚀 Stratus Red Team Commands

### Basic Operations
```bash
# List all available attacks
stratus list

# Get attack details
stratus show aws.credential-access.ec2-get-password-data

# Warm up attack environment
stratus warmup aws.credential-access.ec2-get-password-data

# Execute attack
stratus detonate aws.credential-access.ec2-get-password-data

# Cleanup resources
stratus cleanup aws.credential-access.ec2-get-password-data
```

### Common Attack Scenarios
```bash
# EC2 credential access
stratus detonate aws.credential-access.ec2-get-password-data

# IAM privilege escalation
stratus detonate aws.privilege-escalation.iam-backdoor-role

# CloudTrail logging disruption
stratus detonate aws.defense-evasion.cloudtrail-event-selectors

# Security group modification
stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress
```

## 🔒 Security Best Practices

### IAM
- Use MFA for all IAM users
- Implement least privilege access
- Rotate access keys regularly
- Monitor IAM activity with CloudTrail

### Wazuh
- Keep Wazuh updated
- Regularly update rules and decoders
- Monitor Wazuh manager health
- Configure alerting for critical events

### Stratus Red Team
- Run in a dedicated test account
- Clean up after tests
- Document test results
- Review and update attack scenarios regularly

## 🐛 Troubleshooting

### Common Issues

#### Wazuh Not Starting
```bash
# Check service status
sudo systemctl status wazuh-manager

# Check logs
sudo tail -n 100 /var/ossec/logs/ossec.log
```

#### AWS Permission Issues
```bash
# Verify IAM permissions
aws sts get-caller-identity

# Check effective permissions
aws iam simulate-principal-policy \
    --policy-source-arn arn:aws:iam::123456789012:user/my-user \
    --action-names s3:ListBucket
```

## 🔗 Resources

### Official Documentation
- [Wazuh Documentation](https://documentation.wazuh.com/current/index.html)
- [Stratus Red Team Docs](https://stratus-red-team.cloud/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Tutorials & Guides
- [Wazuh + Stratus Red Team Integration](https://wazuh.com/blog/adversary-emulation-on-aws-with-stratus-red-team-and-wazuh/)
- [AWS Vault Guide](https://github.com/99designs/aws-vault)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

### Tools
- [Wazuh Ruleset Update](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-update/index.html)
- [Stratus Red Team GitHub](https://github.com/DataDog/stratus-red-team)
- [AWS CLI Reference](https://awscli.amazonaws.com/v2/documentation/)

## 📝 Change Log

### 2025-10-08
- Initial project setup
- Integrated Wazuh with AWS CloudTrail
- Configured Stratus Red Team for attack simulation
- Implemented secure IAM roles and policies

---
*Last Updated: October 8, 2025*
 
## Notes (my takeaways)
- 


## Habit-Checkin
### {date} {time} - {duration}
- **What I did**: 
- **Blockers**: 
- **Next Step**: 

