The apache-access-summarizer script parses apache-like log files and summarizes the top countries and top IP addresses received by the server. 
This script is executed periodically, controlled by the cronjobs file, and reviews the log entries for recent log entries controlled by the environment variables. See the script for the required contents of .env.
