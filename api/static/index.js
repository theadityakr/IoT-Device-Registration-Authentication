window.addEventListener("load", () => {
  const loader = document.querySelector(".loader");

  loader.classList.add("loader--hidden");

  loader.addEventListener("transitionend", () => {
    document.body.removeChild(loader);
  });
});





document.getElementById("openPopup").addEventListener("click", function() {
  document.getElementById("popupContainer").style.display = "block";
});

document.getElementById("closePopup").addEventListener("click", function() {
  document.getElementById("popupContainer").style.display = "none";
});
