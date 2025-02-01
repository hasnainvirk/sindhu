# filepath: /home/pneuma/PlayGround/swedish-buddy/main/app.py
"""
Main entry point for the CDK application.
This script sets up the logging configuration and initializes the CDK app.
"""
import os
from dotenv import load_dotenv
import boto3
import aws_cdk as cdk

from stacks.landing_zone import LandingZone as lz

load_dotenv()

PROFILE_NAME = os.getenv("PROFILE_NAME")

# Create a boto3 client
boto3.Session(profile_name=PROFILE_NAME)
app = cdk.App()

# Instantiate stacks
lz_stack = lz(app, "Sindhu-LandingZone")

app.synth()
