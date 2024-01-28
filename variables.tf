variable "region" {
  description = "The region to deploy the resources"
  default     = "us-west-2"
}

variable "instance_type" {
  description = "The type of instance to deploy"
  default     = "t2.micro"
}