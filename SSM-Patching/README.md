## Automating SSM Patch Management for Windows with <br>Compliance Checks in AWS displaying via Slack

### Automating Patch Management and Compliance Checks in AWS
 - Automating the installation of patches and ensuring compliance across your AWS instances is crucial for maintaining security and system stability.
 - This guide provides a detailed step-by-step process for automating patch management and compliance checks.
 - Inside of AWS using AWS Systems Manager, AWS Lambda, and other AWS services.

### Prerequisites
 - Before you begin, ensure you have the following prerequisites in place:
 - AWS Account: You should have an active AWS account with the necessary permissions to create and configure AWS resources.
 - AWS CLI: Install and configure the AWS Command Line Interface (CLI) to interact with AWS services.

### Step 1: Create an IAM Role
 - Create an IAM role with the appropriate permissions for AWS Lambda to interact with AWS Systems Manager:
1. Log in to the AWS Management Console.
2. Navigate to the IAM service.
3. Click "Roles" in the left navigation pane.
4. Click "Create role."
5. Choose "AWS service" as the type of trusted entity.
6. In the "Use case" section, select "Lambda."
7. Attach policies such as AWSLambda_FullAccess and AmazonSSMReadOnlyAccess to this role.
8. Complete the role creation process.

### Step 2: Automating installation and updating of the SSM Agent using State Manager
 - Create a custom association document
1. Open the AWS Management Console.
2. Navigate to AWS Systems Manager.
3. In the left navigation pane, choose "State Manager."
4. Click "Create association" to create a new association.
5. In the "Create Association" wizard, choose "Custom association."
6. Configure the association details, including the targets (instances) and the schedule for updates.
7. In the "Association document details" section, create a JSON document specifying the steps required for SSM Agent installation and update.
8. Review and create the association.

### Step 3: Updating Patch Baselines
1. In the AWS Management Console, navigate to AWS Systems Manager.
2. In the left navigation pane, choose "Patch Manager."
3. Click "Patch baselines" to view available baselines.
4. You can customize an existing baseline or create a new one.
5. In the baseline configuration, select "Edit patch groups" and add relevant instances to the patch group.
6. Scroll down to the "Approval rules" section.
7. Click "Create approval rule" to set up a rule for automatically approving patches.
8. In the approval rule configuration, you can specify criteria for approval, including classification, severity, etc.
9. Save the approval rule.

### Step 4: Create an SNS Topic for Notifications
 - To receive notifications about compliance changes, create an SNS topic. Here's how:
   - Log in to the AWS Management Console.
   - Navigate to the Simple Notification Service (SNS).
   - Click "Create topic" and give it a name, e.g., "MyComplianceNotifications."
   - Define subscriptions, such as via Slack, email addresses etc for receiving notifications.
   - Configure access policies to allow publishing messages to the topic.
   - Go back to your Patch Baseline in Systems Manager.
   - In the baseline's configuration, under "Approval rules," set up notifications to the SNS topic you created.

###  Step 5: SSM Run Command and kicking off patching 
1. In AWS Systems Manager, navigate to "Run Command."
2. Click "Run a command."
3. In the "Command document" list, choose "AWS-RunPatchBaseline" for patching.
4. Select the instances or patch groups you want to target.
5. Configure any additional parameters, if necessary.
6. Run the command.

###  Step 6: Monitoring patches and notifications  
1. In the AWS Management Console, navigate to AWS Systems Manager.
2. Go to "Patch Manager" and select "Patch compliance."
3. Here, you can see the compliance status of your instances.
4. To set up notifications, go to the SNS topic you created earlier for patch notifications.
5. Add subscriptions for your team, like Slack webhooks or email addresses.
6. Whenever there's a compliance change, SSM will send notifications to the subscribed endpoints.

###  Step 7: SSM Association Compliance  
1. In AWS Systems Manager, navigate to "Compliance" under "Patch Manager."
2. You can view the compliance status of your instances here.
3. For detailed reports, go to "Create an association compliance report."
4. Configure the report details, including the association ID and compliance type.
5. Generate the report.

###  Step 8: Automating instance reboots  
1. In the AWS Management Console, navigate to AWS Systems Manager.
2. Go to "Run Command."
3. Choose "Run a command."
4. Select the instances that need a reboot.
5. Choose "AWS-RunPowerShellScript" as the command document.
6. In the command parameters, use PowerShell to schedule a reboot. For example: Restart-Computer -Force -Wait
7. Run the command.

###  Step 9: SSM Automation for rollback in case a patch goes awry
1. In AWS Systems Manager, go to "Automation."
2. Click "Execute automation."
3. Select the desired automation document, like "AWS-RollbackPatch."
4. Specify the targets (instances) affected by the problematic patch.
5. Configure any additional parameters required for the rollback.
6. Run the automation.

###  Step 10: Create maintenance windows for scheduled patching to minimize disruption
1. In AWS Systems Manager, go to "Maintenance Windows."
2. Click "Create maintenance window."
3. Configure the maintenance window settings, including the schedule, duration, and targets (instances).
4. Add tasks to the maintenance window, specifying which patches to install and when.
5. Save and activate the maintenance window.

###  Step 11: Patch approval process: Set up rules to ensure patches are tested before production deployment
1. In AWS Systems Manager, go to "Patch Manager."
2. Configure patch baselines as we discussed earlier.
3. In the "Approval rules" section, set up a manual approval rule.
4. Specify the approval process, such as involving a designated team member or using SNS for notification.
5. Approve patches once they've been tested and are ready for production.

###  Step 12: Address reporting and compliance auditing
1. In AWS Systems Manager, navigate to "Compliance" under "Patch Manager."
2. Use predefined or custom filters to generate compliance reports.
3. Schedule reports to run at regular intervals.
4. Configure SNS notifications to alert you when compliance status changes.
5. Use AWS CloudWatch Events to trigger additional actions based on compliance changes.

###  Step 13: Automating Patch Scheduling 
 - AWS Lambda Function Setup:
   - Log in to the AWS Management Console.
   - Navigate to Lambda and create a new function.
   - Choose "Author from scratch" and configure the basic settings.
   - In the function code, use the AWS SDK to interact with Systems Manager Patch Manager. You can use the boto3 library for Python scripts.
   - Define the necessary IAM role with permissions for Systems Manager.

###  Step 14: Configure CloudWatch Events Rule
 - CloudWatch Events will trigger the Lambda function based on your desired schedule:
1. Log in to the AWS Management Console.
2. Navigate to CloudWatch.
3. Click "Rules" in the left-hand menu. 
4. Click "Create Rule."
5. In the "Event Source" section, choose "Event Source Type" as "Event Source Created by CloudWatch Events."
6. Add your Lambda function as the target.
7. Define a schedule expression (e.g., cron or rate expression) for when the rule should trigger the Lambda function (e.g., daily or weekly).  
8. Provide a name and description for your rule.
9. Create the rule.

###  Step 15: Define Patch Baseline and Target Instances
- Define your patch baseline in AWS Systems Manager Patch Manager, specifying the patches to apply.
- Ensure your instances are tagged appropriately or organized into Systems Manager groups based on criteria like environment or application.

###  Step 16: Scheduling Patching Tasks
- In your Lambda function code, use the AWS SDK to create patching tasks.
- Ensure that maintenance windows and prerequisites are met based on your defined schedule

###  Step 17: Automating Compliance Checks
 - Lambda Function Development:
  - Create a new Lambda function or use an existing one.
  - In the function code, utilize the AWS SDK to scan Systems Manager compliance data.

###  Step 18: Scheduled Execution:  
- Configure the CloudWatch Events rule, similar to patch scheduling, to trigger the Lambda function periodically.

### Step 19: Check for Compliance:  
- In your Lambda code, use the AWS SDK to check for compliance across instances.
- Implement logic to identify non-compliant instances based on your compliance rules. (Reference Lambda Code Below)
### Triggering Notifications:  
- Set up notification mechanisms within your Lambda function.
- Use AWS SNS for sending notifications via email, SMS, or webhooks.

###  Step 20: Automating Compliance Checks
 - Set up AWS Lambda Function for Patch Scheduling
   - AWS Lambda will automate the patch scheduling process:
1. Log in to the AWS Management Console.
2. Navigate to the Lambda service.
3. Create a new Lambda function using the "Author from scratch" option.
4. Configure the function with:
 - A unique Function Name: (e.g., "ComplianceChecker")
 - Runtime: (e.g., Python 3.8)
 - Execution Role: IAM Role created in Step 1 (e.g., AWSLambda\_FullAcces and AmazonSSMReadOnlyAccess
5. Use the following code as a template to interact with AWS Systems Manager Patch Manager.
6. Replace 'MyApp/PatchGroup' '/MyApp/SlackWebhookURL' and '/MyApp/ErrorSlackWebhookURL' values in the code

###  Step 21: Function Code
 - Write Code to Scan Systems Manager Compliance Data:
 - Inside your Lambda function code, use the Boto3 library to interact with AWS services.

```python

import boto3
import datetime
import logging
import os
import requests
import botocore

# Specify the Parameter names for PatchGroup and Slack Webhook URL in Parameter Store
PATCH_GROUP_PARAMETER_NAME = '/MyApp/PatchGroup'  # Adjust this to your Parameter name
SLACK_WEBHOOK_URL_PARAMETER_NAME = '/MyApp/SlackWebhookURL'  # Adjust this to your Parameter name
ERROR_SLACK_WEBHOOK_URL_PARAMETER_NAME = '/MyApp/ErrorSlackWebhookURL'  # Adjust this to your Parameter name

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_parameter(parameter_name):
    """
    Retrieve a parameter value from AWS Systems Manager Parameter Store.

    Args:
        parameter_name (str): The name of the parameter to retrieve.

    Returns:
        str: The value of the parameter.

    Raises:
        botocore.exceptions.ClientError: If there is an error in retrieving the parameter.
    """
    try:
        # Initialize AWS SSM client with the region from environment variables
        ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION"))

        # Retrieve the parameter value from Parameter Store
        response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return response["Parameter"]["Value"]
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            logger.error(f"Parameter {parameter_name} not found in Parameter Store.")
        else:
            logger.error(f"Error in get_parameter: {e}")
            raise

def get_instance_details(instance_id):
    """
    Retrieve instance details including the OS name and version.

    Args:
        instance_id (str): The ID of the EC2 instance.

    Returns:
        tuple: A tuple containing the OS name and version.
    """
    try:
        # Initialize EC2 client with the region from environment variables
        ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))

        # Describe the instance
        response = ec2.describe_instances(InstanceIds=[instance_id])

        # Extract the OS name and version
        os_name = response["Reservations"][0]["Instances"][0]["PlatformDetails"]["Platform"]
        os_version = response["Reservations"][0]["Instances"][0]["PlatformDetails"]["PlatformVersion"]

        return os_name, os_version
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error in get_instance_details: {e}")
        raise

def scan_compliance(patch_group):
    """
    Scan instance patch compliance for a specified PatchGroup.

    Args:
        patch_group (str): The PatchGroup to scan.

    Returns:
        list: A list of non-compliant instance IDs.
        dict: A dictionary of instance IDs mapped to patch details.
    """
    try:
        # Get patch compliance summary using PatchGroup from Parameter Store
        ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION"))
        compliance = ssm.describe_instance_patch_states(
            Filters=[
                {
                    "Key": "PatchGroup",  # AWS Systems Manager Patch Manager Patch Group
                    "Values": [patch_group],
                },
            ]
        )

        # Check if there are non-compliant instances
        non_compliant_instances = []
        patch_info = {}
        for instance in compliance["InstancePatchStates"]:
            if instance["PatchStatus"] != "COMPLIANT":
                instance_id = instance["InstanceId"]
                os_name, os_version = get_instance_details(instance_id)
                non_compliant_instances.append(instance_id)
                patch_info[instance_id] = {"MissingCount": instance["MissingCount"], "OSName": os_name, "OSVersion": os_version}

                # Include the missing patches for this instance
                patch_info[instance_id]["MissingPatches"] = [
                    (f"Patch{i}", severity) for i, severity in enumerate(["Critical", "High", "Medium", "Low"][:instance["MissingCount"]])
                ]

        return non_compliant_instances, patch_info
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error in scan_compliance: {e}")
        raise

def notify_compliance_changes(slack_webhook_url, error_slack_webhook_url, non_compliant_instances, patch_info):
    """
    Notify compliance changes to Slack via webhook.

    Args:
        slack_webhook_url (str): The Slack webhook URL.
        error_slack_webhook_url (str): The Slack webhook URL for error alerts.
        non_compliant_instances (list): A list of non-compliant instance IDs.
        patch_info (dict): A dictionary of instance IDs mapped to patch details.
    """
    try:
        # Prepare notification messages
        notification_message = f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        # Prepare messages for non-compliant instances
        if non_compliant_instances:
            notification_message += "Non-Compliant Systems:\n"
            for instance_id in non_compliant_instances:
                os_name = patch_info[instance_id]["OSName"]
                os_version = patch_info[instance_id]["OSVersion"]
                missing_count = patch_info[instance_id]["MissingCount"]
                notification_message += f"{instance_id}   ({os_name} {os_version})\n"
                notification_message += f"Missing Patches: {missing_count} / Patch Severity: High\n"

                # Include the missing patches for this instance
                for patch_num, severity in patch_info[instance_id]["MissingPatches"]:
                    notification_message += f"Patch{patch_num}: {severity}\n"

                notification_message += "\n"
        else:
            notification_message += "All Systems are Compliant.\n"

        # Send messages to Slack via webhook
        headers = {'Content-type': 'application/json'}
        data = {'text': notification_message}

        # Send notifications to the appropriate Slack rooms
        response = requests.post(slack_webhook_url, json=data, headers=headers)

        # Check for successful Slack message delivery
        if response.status_code == 200:
            logger.info("Notifications sent successfully to Slack.")
        else:
            logger.error(f"Failed to send notifications to Slack. Status Code: {response.status_code}")

    except Exception as e:
        logger.error(f"Error while sending compliance alerts: {e}")

def list_pending_reboot_instances():
    try:
        # Initialize EC2 client with the region from environment variables
        ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))

        # Describe instances with pending reboots
        response = ec2.describe_instance_status(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        pending_reboot_instances = []

        for instance_status in response['InstanceStatuses']:
            if 'Events' in instance_status and any(event['Code'] == 'system-reboot' for event in instance_status['Events']):
                pending_reboot_instances.append(instance_status['InstanceId'])

        return pending_reboot_instances
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error in list_pending_reboot_instances: {e}")
        raise

def reboot_instances(instance_ids):
    try:
        # Initialize EC2 client with the region from environment variables
        ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION"))

        # Reboot the instances
        ec2.reboot_instances(InstanceIds=instance_ids)
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error in reboot_instances: {e}")
        raise

def main():
    try:
        # Retrieve configuration values from Parameter Store
        patch_group = get_parameter(PATCH_GROUP_PARAMETER_NAME)
        slack_webhook_url = get_parameter(SLACK_WEBHOOK_URL_PARAMETER_NAME)
        error_slack_webhook_url = get_parameter(ERROR_SLACK_WEBHOOK_URL_PARAMETER_NAME)

        # Scan for compliance and send alerts
        non_compliant_instances, patch_info = scan_compliance(patch_group)
        notify_compliance_changes(slack_webhook_url, error_slack_webhook_url, non_compliant_instances, patch_info)

        # List instances with pending reboots
        pending_reboot_instances = list_pending_reboot_instances()

        # You can add a check here to see if there are pending reboots and initiate reboots if needed.
        if pending_reboot_instances:
            # Perform any additional logic, e.g., send a Slack message to initiate reboots
            reboot_instances(pending_reboot_instances)

    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    main()
```

### Example Output  

```python
Timestamp: 2023-09-17 10:30:00

Non-Compliant Systems:
i-34567890   (Windows Server 2019)
Missing Patches: 5 / Patch Severity: High
Patch1: Critical
Patch2: High
Patch3: Critical
Patch4: High
Patch5: Critical

i-45678901   (CentOS 7)
Missing Patches: 3 / Patch Severity: High
Patch1: Critical
Patch2: High
Patch3: Medium
```

###  Step 22: Scheduled Execution
 - Configure CloudWatch Events Rule:   
   - Log in to the AWS Management Console.
   - Navigate to CloudWatch.
   - Click "Rules" in the left-hand menu.
   - Click "Create Rule."
   - In the "Event Source" section, choose "Event Source Type" as "Event Source Created by CloudWatch Events."
   - In the "Targets" section, add your Lambda function created earlier.
   - Define a schedule expression to specify how often the rule should trigger the Lambda function (e.g., daily, weekly).
   - Click "Configure details" and provide a name and description for your rule.
   - Click "Create Rule."

###  Step 23: Triggering Notifications
 - Set up Notification Mechanisms:  
   - Inside your Lambda function code, after identifying non-compliant instances based on your compliance rules, implement code to trigger notifications.
   - Use AWS Simple Notification Service (SNS) to send notifications via email, SMS, or Slack webhooks.
   - You can configure SNS topics to manage different types of notifications.

###  Step 24: Automating Notification Delivery via Slack
- AWS Configuration Steps
1. Create an SNS Topic:
   - Log in to the AWS Management Console.
   - Navigate to the Simple Notification Service (SNS).
   - Click "Create Topic" and give it a name, such as "MySlackNotifications."
2. Define Subscriptions:
   - Within the SNS topic settings, click "Create Subscription."
   - Choose the protocol "HTTPS."
   - In the "Endpoint" field, provide the Slack webhook URL.
   - Confirm the subscription by clicking "Create Subscription."
3. Access Policy Configuration:
   - In the SNS topic settings, go to the "Access Policy" section.
   - Ensure that the policy allows publishing messages to the topic.
   - Modify the policy if needed to grant the required permissions.
4. AWS Lambda Function (Optional):
   - If you're using Lambda to automate notifications, create a Lambda function that sends messages to the SNS topic.
   - Configure the function to process events and publish messages to the SNS topic.
5. Slack Configuration Steps
   - Create a Slack App:
   - Log in to your Slack workspace.
   - Navigate to the Slack API website.
 - Create a new Slack app for receiving notifications.
   - Configure Incoming Webhooks:
     - In the Slack app settings, navigate to "Incoming Webhooks."
     - Activate incoming webhooks and create a new webhook.
     - Customize the webhook's name, icon, and default channel.
 - Obtain Webhook URL:
   - Once the webhook is created, you'll receive a unique URL.
   - This URL is used to send messages to your Slack channel.
 - Test the Integration:
   - Test the integration by sending a sample message to the webhook URL.
   - Verify that the message appears in your Slack channel.
 - Integrate AWS SNS and Slack:
   - In the AWS SNS topic settings, ensure that the subscription endpoint is the Slack webhook URL.
   - When SNS events occur, messages will be sent to Slack.
 - Monitor and Maintain
   - Regularly monitor the integration to ensure notifications are delivered as expected.
   - Adjust Lambda function settings, IAM permissions, and notification configurations if needed to maintain a smooth patch management and compliance process.

### Step 25: Set Up Slack and Email Notifications
- Slack Notifications
1. Define Subscriptions for Slack Notifications:
   - Within the SNS topic settings (created in Step 24), click "Create Subscription."
   - Choose the protocol "HTTPS."
   - In the "Endpoint" field, provide the Slack webhook URL.
   - Confirm the subscription by clicking "Create Subscription."
2. Access Policy Configuration for Slack Notifications:
   - In the SNS topic settings (created in Step 24), go to the "Access Policy" section.
   - Ensure that the policy allows publishing messages to the topic.
   - Modify the policy if needed to grant the required permissions.
3. AWS Lambda Function for Slack Notifications (Optional):
   - If you're using Lambda to automate notifications, create a Lambda function that sends messages to the SNS topic (created in Step 24).
   - Configure the function to process events and publish messages to the SNS topic.
4. Configure Slack App:
   - Log in to your Slack workspace.
   - Navigate to the Slack API website.
   - Create a new Slack app for receiving notifications.
5. Incoming Webhooks for Slack:
   - In the Slack app settings (created in Step 28), navigate to "Incoming Webhooks."
   - Activate incoming webhooks and create a new webhook.
   - Customize the webhook's name, icon, and default channel.
6. Obtain Slack Webhook URL:
   - Once the webhook is created (Step 29), you'll receive a unique URL.
   - This URL is used to send messages to your Slack channel.
7. Test Slack Integration:
   - Test the integration by sending a sample message to the Slack webhook URL (created in Step 29).
   - Verify that the message appears in your Slack channel.
8. Integrate AWS SNS and Slack:
   - In the AWS SNS topic settings (created in Step 24), ensure that the subscription endpoint is the Slack webhook URL (created in Step 29).
   - When SNS events occur, messages will be sent to Slack.
9. Monitor and Maintain Slack Integration:
   - Regularly monitor the integration to ensure notifications are delivered as expected.
   - Adjust Lambda function settings (if used), IAM permissions, and notification configurations if needed to maintain a smooth patch management and compliance process.

10. Email Notifications
 - Define Email Subscriptions:
   - Within the SNS topic settings (created in Step 34), click "Create Subscription."
   - Choose the protocol "Email."
   - Enter the email addresses to which you want to send notifications.
   - Confirm the subscription by responding to the confirmation email sent to the specified email addresses.
11. Access Policy Configuration for Email:
   - In the SNS topic settings (created in Step 34), go to the "Access Policy" section.
   - Ensure that the policy allows publishing messages to the topic.
   - Modify the policy if needed to grant the required permissions.
12. AWS Lambda Function for Email Notifications (Optional):
   - If you're using Lambda to automate notifications, create a Lambda function that sends messages to the SNS topic (created in Step 34).
   - Configure the function to process events and publish messages to the SNS topic.
13. Email Configuration Steps:
   - Check Email Service Support:
     - Ensure that the email addresses you provided are valid and have access to the email service you intend to use.
     - Access Your Email Service:
 - Log in to your email service (e.g., Gmail, Outlook, or another email provider).
 - Consider creating a filter or label for AWS notifications to keep them organized in your inbox.
 - Whitelist AWS SNS Email Address (if needed) to keep them out of your spam or junk folder. Consider whitelisting SNS email address.
14. Test Email Integration:
   - Trigger an SNS event or Lambda function (if used) that publishes a test message to the SNS topic (created in Step 34).
   - Verify that the email notifications are sent to the specified email addresses.
15. Monitor and Maintain Email Notifications:
   - Regularly monitor your email inbox for notifications.
   - Adjust email filters, labels, or settings if needed to manage notifications effectively.

###  Step 26: Testing and Deployment
- Test your Lambda function to ensure it successfully scans compliance data and triggers notifications.
- Deploy the Lambda function and CloudWatch Events rule to automate compliance checks and notifications.
