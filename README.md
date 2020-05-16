# AWS CloudWatch Event Rule - Quick Reference

This is a quick reference for security related AWS CloudWatch Event Rule patterns.

## Root User Activity

All IAM (including Root) events go to the us-east-1 region, so these CloudWatch Event Rules must be created in us-east-1 (N. Virginia).

### All Activity

#### Event Pattern

```
{
  "detail-type": [
    "AWS Console Sign In via CloudTrail",
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)

```
CWERuleAllRootActivity: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity
      Description: "All Root Activity"
      EventPattern: 
        detail-type:
        - "AWS Console Sign In via CloudTrail"
        - "AWS API Call via CloudTrail"
        detail:
            userIdentity:
                type:
                - Root
      State: "ENABLED"

```

### Root Login

#### Event Pattern

```
{
  "detail": {
    "eventName": [
      "ConsoleLogin"
    ],
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)
```
CWERuleRootLogin: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-login
      Description: "Root Password Change"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - ConsoleLogin
      State: "ENABLED"
```

### Password Modification

#### Event Pattern

```
{
  "detail": {
    "eventName": [
      "PasswordUpdated",
      "PasswordRecoveryRequested",
      "PasswordRecoveryCompleted"
    ],
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)

```
CWERuleRootChangePassword: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-password
      Description: "Root Password Change"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - PasswordUpdated
            - PasswordRecoveryRequested
            - PasswordRecoveryCompleted
      State: "ENABLED"
```

### Email Update

#### Event Pattern

```
{
  "detail": {
    "eventName": [
      "EmailUpdated"
    ],
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)

```
CWERuleRootEmailUpdate: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-email-update
      Description: "Root Email Update"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - EmailUpdated
      State: "ENABLED"
```

### Security Questions or Contacts Modification 

#### Event Pattern

```
{
  "detail": {
    "eventName": [
      "SetAdditionalContacts",
      "SetSecurityQuestions"
    ],
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)

```
CWERuleAccountSettingsUpdate: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-question-contacts-update
      Description: "Root Account settings update"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - SetAdditionalContacts
            -SetSecurityQuestions
      State: "ENABLED"
```

### MFA Modification

#### Event Pattern

```
{
  "detail": {
    "eventName": [
      "CreateVirtualMFADevice",
      "EnableMFADevice",
      "DeactivateMFADevice",
      "DeleteVirtualMFADevice"
    ],
    "userIdentity": {
      "type": [
        "Root"
      ]
    }
  }
}
```

#### AWS CloudFormation Resource (YAML)

```
CWERuleRootMFA: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-mfa-update
      Description: "Root MFA Update"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - CreateVirtualMFADevice
            - EnableMFADevice
            - DeactivateMFADevice
            - DeleteVirtualMFADevice
      State: "ENABLED"
```

## Amazon GuardDuty

### All Findings

```
CWERuleGuardDutyFindingAll: 
	Type: "AWS::Events::Rule"
	Properties: 
		Name: example-guardduty-findings-all
		Description: "All GuardDuty Findings"
		EventPattern: 
			source:
			- aws.guardduty
			detail-type:
			- "GuardDuty Finding"
		State: "ENABLED"
```

### All IAM Findings

```
CWERuleGuardDutyIAMFindingAll: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-guardduty-iam-findings
      Description: "GuardDuty: AWS IAM Findings"
      EventPattern: 
        source:
        - aws.guardduty
        detail-type:
        - "GuardDuty Finding"
        detail:
          resource:
            resourceType: 
            - AccessKey
      State: "ENABLED"
```

### Specific Finding
 
```
CWERuleGuardDutyFindingSSHBruteForce: 
   Type: "AWS::Events::Rule"
   Properties: 
      Name: example-guardduty-finding-sshbruteforce
      Description: "GuardDuty Finding: UnauthorizedAccess:EC2/SSHBruteForce"
      EventPattern: 
        source:
        - aws.guardduty
        detail:
          type:
          - "UnauthorizedAccess:EC2/SSHBruteForce"
      State: "ENABLED"
```
 
 