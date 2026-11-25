/**
 * api-client.js — Planted API endpoints, admin routes, and IDOR candidates.
 */

// ============================================================
// API endpoints (LinkFinder-style extraction targets)
// ============================================================

var ApiClient = {
    baseUrl: "/api/v2",

    getUsers: function() {
        return fetch("/api/v2/users");
    },

    getUser: function(id) {
        return fetch("/api/v2/users/" + id + "/profile");
    },

    updateUser: function(id, data) {
        return axios.post("/api/v1/users/" + id + "/update", data);
    },

    deleteAccount: function(accountId) {
        return fetch("/api/v2/accounts/" + accountId + "/delete");
    },

    // Admin / internal routes
    getAdminDashboard: function() {
        return fetch("/api/v2/admin/dashboard");
    },

    getInternalMetrics: function() {
        return fetch("/internal/metrics/prometheus");
    },

    debugInfo: function() {
        return fetch("/api/debug/stack-trace");
    },

    getSwagger: function() {
        return fetch("/api/swagger/v1/swagger.json");
    },

    graphqlEndpoint: "/api/graphql",

    // IDOR candidates — routes with object IDs
    getOrder: function(orderId) {
        return fetch("/api/v2/orders/" + orderId);
    },

    getInvoice: function(invoiceId) {
        return fetch("/api/v1/invoices/" + invoiceId + "/download");
    },

    getMessage: function(msgId) {
        return fetch("/api/v2/messages/" + msgId);
    },

    getDocument: function(docId) {
        return fetch("/api/v2/documents/" + docId + "/view");
    },

    // Versioned endpoints
    legacyLogin: "/v1/auth/login",
    currentLogin: "/v2/auth/login",
    betaFeature: "/api/beta/feature-flags",

    // Config endpoint
    getConfig: function() {
        return fetch("/api/v2/config/settings");
    },

    // Report endpoint
    getReport: function(reportId) {
        return fetch("/api/v1/reports/" + reportId);
    },
};

// Another pattern: string concatenation
var webhookUrl = "https://api.internal.megacorp.com/webhooks/notify";
var healthCheck = "/api/health";
var managementConsole = "/admin/console/manage";
