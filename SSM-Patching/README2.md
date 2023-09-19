## Slack Lamba Notifications Trigger & Authentication for SSM Windows Patching

### Custom Credentials vs AWS IAM User Accounts for Slack commands

-    AWS User Accounts: You can use AWS Identity and Access Management (IAM) to manage user accounts and access permissions within the AWS ecosystem. This is suitable for authenticating users for AWS services and resources, such as AWS Console access and AWS APIs.

- Custom Credentials: In the case of Slack commands that interact with AWS resources, it's often more practical to implement custom credentials and authentication mechanisms. This is because Slack commands are typically used by users external to AWS, and you may not want to directly tie AWS IAM users to external users.

- Separation of Concerns: Using custom credentials allows you to have greater control and separation of concerns. You can manage Slack command authentication independently from AWS IAM user management. It also provides flexibility to implement multi-factor authentication (like OTP) and other security measures tailored to your application's needs.

- Custom credentials and authentication for Slack commands initiated by external users is best practice.

- Step-by-step instructions for implementing the secure authentication mechanism.

### Step 1: Set Up a Custom Authentication Endpoint

    Create an AWS Lambda Function for Authentication:
        Log in to your AWS Management Console (https://aws.amazon.com/).
        Open the Lambda service by clicking on "Services" and selecting "Lambda" under "Compute."

    Create a New Lambda Function:
        Click the "Create function" button.

    Choose Author from Scratch:
        In the "Create function" page, select "Author from scratch."

    Configure Basic Function Information:
        Enter a name for your function, such as "SlackAuthenticationEndpoint."
        Choose the runtime. Python is a common choice, so you can select "Python 3.8" or another version you prefer.
        In the "Execution role" section, create a new role from AWS policy templates.
        Or use an existing role that has the necessary permissions to interact with your authentication data store.

    Create Function:
        Click the "Create function" button to create your Lambda function.

    Customize Your Lambda Function Code:
        Within your Lambda function, implement the authentication logic, including username and password verification and optional OTP validation.

    Configure API Gateway:
        Create a new API Gateway by clicking on "Services" and selecting "API Gateway" under "Networking & Content Delivery."
        Follow the API Gateway wizard to create a new API and define a resource and method (e.g., POST) that will be used to handle authentication requests.
        Set the integration type to Lambda Function and select the Lambda function you created for authentication.
        Deploy the API to create a public endpoint for authentication.

### Step 2: Authentication Logic

    Implement Authentication Logic in Lambda:
        In your Lambda function, write code to handle user authentication.
        Implement username and password verification logic. You can use a secure data store (like AWS Secrets Manager) to store and retrieve user credentials.

    Username and Password Verification:
        Store authorized usernames and securely hashed passwords in your data store.
        When a request comes in, verify the provided username and hashed password against your stored data.
        If OTP is required, implement OTP generation, sharing, and validation.

### Step 3: Slack Command Integration

    Modify Existing Slack Command Handler:
        In your existing Lambda function that handles Slack commands, integrate the custom authentication.
        When the /reboot-instances command is invoked, initiate the authentication process.

    Send Authentication Request to Custom Endpoint:
        When a user runs the /reboot-instances command in Slack, Slack will send a request to your custom authentication endpoint.
        This request should include the user's username, password, and OTP (if required).

    Custom Authentication Logic:
        In your Lambda function, verify the provided credentials and OTP (if used) by calling your custom authentication endpoint.
        Ensure the response from the custom authentication endpoint indicates whether the user is authorized.

### Step 4: Implement OTP Generation and Verification (Optional)

    OTP Generation:
        If you're using OTP for added security, implement OTP generation and sharing with authorized users.
        You can use libraries like PyOTP for OTP generation.

    OTP Verification:
        In your custom authentication endpoint, implement OTP verification.
        Ensure that the OTP provided by the user matches the expected OTP for their account.

### Step 5: Respond to Slack

    Send Response to Slack:
        After successful authentication and authorization, send a response to the Slack channel confirming that the /reboot-instances command has been initiated.

### Step 6: Secure Storage of User Data

     Securely Store User Data:
        Ensure that user credentials, including passwords and OTPs (if used), are securely stored.
        Consider using AWS Parameter Store or AWS Secrets Manager or another secure storage solution.

### Lambda Code

```python
import os
import json
import boto3
import botocore
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all

# Store SECRET_TOKEN_PARAMETER_NAME in /MyApp/SecretToken - Random alpha numeric - Ex: 7#c9a$8*5%6&!@k3=5%4^$8#78
# Store SLACK_BOT_TOKEN_PARAMETER_NAME in /MyApp/SlackBotToken - Generated when setting up Webhooks/OAuth in Slack 
# Store OTP_SECRET_PARAMETER_NAME in /MyApp/SlackUsers/{username}/OTPSecret - Random alpha numeric number - Ex: SA6Q3N84IQJB67LR (Must be unique)

# Define names of Parameters in AWS Systems Manager Parameter Store
SECRET_TOKEN_PARAMETER_NAME = '/MyApp/SecretToken'  # Adjust to your Parameter Store Name
SLACK_BOT_TOKEN_PARAMETER_NAME = '/MyApp/SlackBotToken'  # Adjust to your Parameter Store Name
OTP_SECRET_PARAMETER_NAME_FORMAT = '/MyApp/SlackUsers/{username}/OTPSecret' # Adjust to your Parameter Store Name

# Initialize AWS SSM client with the region from environment variables
ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION"))

# Retrieve the SECRET_TOKEN from Parameter Store
secret_token = None
try:
    response = ssm.get_parameter(Name=SECRET_TOKEN_PARAMETER_NAME, WithDecryption=True)
    secret_token = response["Parameter"]["Value"]
except botocore.exceptions.ClientError as e:
    print(f"Error in getting SECRET_TOKEN from Parameter Store: {e}")
    raise

# Retrieve the Slack Bot Token from Parameter Store
slack_bot_token = None
try:
    response = ssm.get_parameter(Name=SLACK_BOT_TOKEN_PARAMETER_NAME, WithDecryption=True)
    slack_bot_token = response["Parameter"]["Value"]
except botocore.exceptions.ClientError as e:
    print(f"Error in getting Slack Bot Token from Parameter Store: {e}")
    raise

# Initialize Slack WebClient with the Bot Token
slack_client = WebClient(token=slack_bot_token)

@xray_recorder.capture("process_slack_command")
def process_slack_command(event, context):
    try:
        # Parse the incoming Slack command
        body = json.loads(event["body"])
        command = body["command"]
        text = body["text"]
        user_id = body["user_id"]
        token = body["token"]  # The token sent by Slack
        username = body.get("username")
        password = body.get("password")
        otp = body.get("otp")  # Optional OTP

        # Check if the token matches your SECRET_TOKEN
        if token != secret_token:
            error_message = "Unauthorized: Invalid token."
            slack_client.chat_postMessage(channel=body["channel_id"], text=error_message)
            return {
                "statusCode": 403,  # Forbidden
                "body": json.dumps({"message": "Unauthorized"}),
            }

        # Check the command and take appropriate actions
        if command == "/reboot-instances":
            # Implement your logic to initiate instance reboots here
            # Verify user authorization and perform the reboots if authorized
            # You can use the user_id to check user permissions

            # Retrieve the OTP secret key from Parameter Store
            otp_secret_parameter_name = OTP_SECRET_PARAMETER_NAME_FORMAT.format(username=username)
            otp_secret = None
            try:
                response = ssm.get_parameter(Name=otp_secret_parameter_name, WithDecryption=True)
                otp_secret = response["Parameter"]["Value"]
            except botocore.exceptions.ClientError as e:
                error_message = f"Error in getting OTP secret key from Parameter Store: {e}"
                slack_client.chat_postMessage(channel=body["channel_id"], text=error_message)
                return {
                    "statusCode": 403,  # Forbidden
                    "body": json.dumps({"message": "Unauthorized"}),
                }

            # Authenticate the user by calling the custom authentication endpoint
            auth_response = authenticate_user(username, password, otp, otp_secret)

            if not auth_response.get("authorized"):
                error_message = "Unauthorized: Invalid authentication."
                slack_client.chat_postMessage(channel=body["channel_id"], text=error_message)
                return {
                    "statusCode": 403,  # Forbidden
                    "body": json.dumps({"message": "Unauthorized"}),
                }

            # For example, you can use the existing code to list pending reboot instances
            # pending_reboot_instances = list_pending_reboot_instances()
            # if pending_reboot_instances:
            #     reboot_instances(pending_reboot_instances)

            # Respond to the user with a message
            message = f"Initiating instance reboots for user {user_id}..."
            slack_client.chat_postMessage(channel=body["channel_id"], text=message)

            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Reboot command initiated"}),
            }
        else:
            return {
                "statusCode": 200,
                "body": json.dumps({"message": f"Unknown command: {command}"}),
            }

    except SlackApiError as e:
        error_message = f"Error sending message to Slack: {e.response['error']}"
        slack_client.chat_postMessage(channel=body["channel_id"], text=error_message)
        raise

    except Exception as e:
        error_message = f"Error processing Slack command: {e}"
        slack_client.chat_postMessage(channel=body["channel_id"], text=error_message)
        raise

# Function to authenticate the user against the custom authentication endpoint
def authenticate_user(username, password, otp, otp_secret):
    # Retrieve the user's stored password from Parameter Store
    user_password_parameter_name = f'/MyApp/SlackUsers/{username}/Password'
    try:
        response = ssm.get_parameter(Name=user_password_parameter_name, WithDecryption=True)
        stored_password = response["Parameter"]["Value"]
    except botocore.exceptions.ClientError as e:
        error_message = f"Error in getting user's stored password from Parameter Store: {e}"
        print(error_message)
        return {"authorized": False}

    # Implement code here to compare the provided password with the stored password
    # Include OTP verification logic if needed
    if password == stored_password:
        # If OTP verification is required, add OTP validation logic here
        # Compare the provided OTP with the OTP generated from otp_secret

        # Example OTP validation:
        if otp == generate_otp(otp_secret):
            return {"authorized": True}
        else:
            return {"authorized": False}
    else:
        return {"authorized": False}

# Function to generate OTP based on the OTP secret
def generate_otp(otp_secret):
    # Implement OTP generation logic here based on the secret
    # This will depend on the OTP algorithm you are using
    # Return the generated OTP as a string
    pass  # Replace with actual OTP generation logic

```
