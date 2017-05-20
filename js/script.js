document.addEventListener("DOMContentLoaded", function() {
  var url = window.location.href;
  var navitems = document.querySelectorAll(".topnav a");

  for (var i = 0; i < navitems.length; i++) {
    var a = navitems.item(i);
    var href = a.getAttribute("href");
    if (url.endsWith(href)) {
      a.classList.add("active");
    }
  }
});
