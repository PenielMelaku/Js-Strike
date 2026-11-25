/**
 * app.js — Main application file with planted client-side execution flaws.
 */

// ============================================================
// 1) DOM XSS: source → sink (high confidence, proximate)
// ============================================================

function renderSearch() {
    var query = location.search.split("q=")[1];  // source: location.search
    document.getElementById("results").innerHTML = "Results for: " + query;  // sink: innerHTML
}

function renderHash() {
    var fragment = document.URL.split("#")[1];  // source: document.URL
    $(".output").html(fragment);                 // sink: jQuery .html()
}

function processReferrer() {
    var ref = document.referrer;         // source: document.referrer
    eval("trackReferrer('" + ref + "')"); // sink: eval()
}

function unsafeWrite() {
    var name = window.name;                // source: window.name
    document.write("<h2>Welcome " + name + "</h2>"); // sink: document.write()
}

function renderComment(comment) {
    var el = document.getElementById("comment-box");
    el.insertAdjacentHTML("beforeend", comment); // sink: insertAdjacentHTML
}

// ============================================================
// 2) Insecure postMessage handler (no origin check)
// ============================================================

window.addEventListener("message", function(event) {
    // BUG: no event.origin check here!
    var data = event.data;
    document.getElementById("msg-output").innerHTML = data.html;
});

// Another one with arrow function
window.addEventListener("message", (e) => {
    // Also missing origin check
    document.body.insertAdjacentHTML("beforeend", e.data.content);
});

// ============================================================
// 3) DOM-based open redirect
// ============================================================

function handleRedirect() {
    var params = new URLSearchParams(location.search);
    var next = params.get("redirect");
    location.href = next;         // redirect sink with URL source
}

function legacyRedirect() {
    var url = document.URL;
    var goto = url.split("goto=")[1];
    location.replace(goto);       // redirect sink
}

function openPopup() {
    var target = location.hash.substring(1);
    window.open(target);          // redirect sink
}

// ============================================================
// 4) Sensitive data in browser storage
// ============================================================

function saveCredentials(token) {
    localStorage.setItem("access_token", token);
    localStorage.setItem("refresh_token", generateRefresh());
    sessionStorage.setItem("private_key", getUserKey());
}

// ============================================================
// 5) Client-side validation
// ============================================================

function computeTotal(cart) {
    var total = 0;
    cart.items.forEach(function(item) {
        total += item.price * item.quantity;    // client-side price computation
    });
    var discount = total * 0.1;
    total -= discount;
    return total;
}

function checkAccess() {
    if (user.isAdmin === true) {
        showAdminDashboard();
    }
    if (currentUser.permission !== "viewer") {
        enableEditing();
    }
}
