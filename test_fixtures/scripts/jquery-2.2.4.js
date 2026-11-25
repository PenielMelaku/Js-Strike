/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */
// FAKE minimal jQuery 2.2.4 for fingerprinting test
// jQuery JavaScript Library v2.2.4
(function(global, factory) {
    "use strict";
    factory(global);
})(typeof window !== "undefined" ? window : this, function(window) {
    var jQuery = function(selector) {
        return new jQuery.fn.init(selector);
    };
    jQuery.fn = jQuery.prototype = {
        jquery: "2.2.4",
        constructor: jQuery,
        init: function(selector) { return this; }
    };
    jQuery.fn.init.prototype = jQuery.fn;
    jQuery.fn.html = function(val) { /* stub */ };
    jQuery.fn.append = function(val) { /* stub */ };
    jQuery.fn.prepend = function(val) { /* stub */ };
    window.jQuery = window.$ = jQuery;
});
