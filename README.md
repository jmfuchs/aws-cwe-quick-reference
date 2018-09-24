# AWS CloudWatch Event Rule - Quick Reference

blah blah blah

## Root User Activity

All IAM (including Root) events go to the us-east-1 region, so these CloudWatch Event Rules must be created in us-east-1 (N. Virginia).

### All Activity

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

##### Rule
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


### Root Password Activity

#### Password Change

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
      State: "ENABLED"
```

##### With SNS Target and Input Transformer

```
CWERuleRootChangePasswordSNS: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-password-with-target
      Description: "Root Password Change with SNS Target"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - PasswordUpdated
            - PasswordRecoveryRequested
      State: "ENABLED"
      Targets: 
        - Arn: 
            Ref: "SNSTopic"
          Id: "SNSTopic-Root-Password-Alert"
          InputTransformer:
            InputTemplate: '"An attempt to change the Root password for account# <account> has been made by <source> (response: <response>). "'
            InputPathsMap:
              account: "$.account"
              source: "$.detail.sourceIPAddress"
              response: "$.detail.responseElements.PasswordUpdated"
```

#### Password Recovery

```
CWERuleRootPasswordRecovery: 
    Type: "AWS::Events::Rule"
    Properties: 
      Name: example-root-activity-password-recovery
      Description: "Root Password Recovery"
      EventPattern: 
        detail:
            userIdentity:
                type:
                - Root
            eventName: 
            - PasswordRecoveryRequested
            - PasswordRecoveryCompleted
      State: "ENABLED"
```

#### Email Update

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

#### MFA Modification

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
 
 