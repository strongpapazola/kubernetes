# SYSTEMS AND SITES RELIABILITY ENGINEER HOMEWORK

**Additional information:**

- You can sign-up for Google Cloud or Microsoft Azure to get free credit, You also can use VPS (Vultr, AWS Lightsail, Digital Ocean). You can use free credit to complete this test. It is not advisable to use AWS since it doesn’t offer free tier for EKS. If you already have paid account for AWS, GCP, or Azure, you can use that instead.

- A gitlab.com private repository should be used with regular commits showing how the logic was evolved.

- We are interested in how you reach a solution as much as in the solution itself. Therefore, you should maintain a proper README for running your solution. The steps written will be followed by the reviewer in order to test the solution.
- We think it's important to automate code testing to ensure no breaking changes on each new commit. It's not only about the presence of test but the test should have good code coverage.

**Deliverables:**

Due **48** **hours** after receiving challenge email:

- The GitLab repository with any code you have written. You can add user $USER to repository as reviewer.

Due **72 hours** after receiving challenge email:

- A writeup detailing your approach, roadblocks, and -if you could not finish the challenge- additional information on how you would further solve the challenge/improve on your submission.

## Challenges

### Kubernetes Cluster

You are supposed to create kubernetes cluster with these specifications:

- Master nodes can only be accessed through authorized network. (You should put a proper instructions to define the authorized network so reviewer could define their own authorized network.)
- Worker nodes can only have 8 pods.
- Kubernetes cluster has it's own VPC.
- Services and Pods have their own subnetwork and NAT for acccessing network outside its own VPC.

You should automate creation of this kubernetes cluster using any automation tool that you are comfortable. It's also better if you could make automated test. This deployment should be idempotent.

### Virtual Machine Template

You are supposed to build a Virtual Image Template (such AMI or GCE Instance Template) with these specifications:

- NginX installed and automatically runs at start up.
- NginX port is the only port that can be accessed from outside localhost.
- NginX port can only be accessed by kubernetes pods and services subnetwork.
- NginX port can only be accessed by services or pods that live on Kubernetes Cluster that you've created before.
- Docker installed and automatically runs at start up.

You should automate creation of this VM template using any automation tool that you are comfortable. You are also supposed to deploy this VM template to your cloud instance (such as EC2 or GCE) and automate the deployment. It should have its own VPC. It's also better if you could make automated test.  This deployment should be idempotent.

### Simple Web Application

You are supposed to build a web application with these specificaitons:

- When accessed it's homepage, it returns only IP of the requestor.
- It's homepage can only be accessed with HTTP GET Method.
- It has good automated test and error handling.

You should create GitLab CI Pipeline that on each commit:

- Runs automated test for newest commit.
- Builds a Docker image (alpine based).
- Deploys it to your cloud instance that you've deployed before.
- Ensures that this docker image is served through NginX port. (You can deploy NginX configuration that forwards packet from docker port to NginX port)

You can build this application using any programming language that you are comfortable to use. You have to make automated test. It has to have good code coverage. This automated deployment should be idempotent.

### Gitlab CI Pipeline

You are supposed to create GitLab CI Pipeline that on each run: 

- Deploys a job to kubernetes cluster to test that your kubernetes cluster can access your web application.
- Only succeeds if it return the NAT IP of your kubernetes pods subnetwork.

You can create this using best practices you believe in. This automated deployment should be idempotent.
