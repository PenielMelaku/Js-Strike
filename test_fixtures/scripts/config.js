/**
 * config.js — Planted secrets and internal infrastructure leakage.
 */

// ============================================================
// Hardcoded secrets
// ============================================================

var AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
var aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

var FIREBASE_CONFIG = {
    apiKey: "AIzaSyC3xGKPMFE1234567890abcdefghijklm",
    authDomain: "myproject-12345.firebaseapp.com",
    databaseURL: "https://myproject-12345.firebaseio.com",
    projectId: "myproject-12345",
    storageBucket: "myproject-12345.appspot.com",
    messagingSenderId: "123456789012",
    appId: "1:123456789012:web:abcdef1234567890"
};

var STRIPE_KEY = "__STRIPE_LIVE_KEY_PLACEHOLDER__";
var STRIPE_PUB = "pk_test_TYooMQauvdEDq54NiTphI7jx";

var SLACK_WEBHOOK = "__SLACK_WEBHOOK_PLACEHOLDER__";
var SLACK_TOKEN = "__SLACK_TOKEN_PLACEHOLDER__";

var GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";

// JWT in a variable
var ADMIN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Generic API key patterns
var config = {
    api_key: "sk-proj-EXAMPLE1234567890abcdefghijklmn",
    client_secret: "dGhpcyBpcyBhIHNlY3JldCB0b2tlbg==",
    password: "SuperS3cretP@ssw0rd!",
};

// Database connection strings
var DB_URI = "mongodb://admin:password123@db.internal.corp:27017/production";
var REDIS_URL = "redis://default:s3cretpass@cache.staging.internal:6379";

// ============================================================
// Internal infrastructure leakage
// ============================================================

var API_BASE = "https://staging-api.megacorp.internal/v2";
var ADMIN_PANEL = "http://10.0.1.50:8080/admin";
var DEV_SERVER = "https://dev.megacorp.com/api/v1";
var JENKINS_URL = "https://jenkins.megacorp.internal:8443/job/deploy-prod";

var S3_BUCKET = "megacorp-user-uploads.s3.amazonaws.com";
var S3_URI = "s3://megacorp-internal-logs";
var S3_ARN = "arn:aws:s3:::megacorp-backup-prod";

var INTERNAL_IP = "192.168.1.100";
var METADATA = "http://169.254.169.254/latest/meta-data/";

// Developer email
var CONTACT = "admin@megacorp.internal";

// CI/CD metadata
var BUILD_INFO = "Built with jenkins-pipeline v3.2.1 on gitlab-ci runner 42";

