var apiKey = "5501257fa83ea9795e11145fee5548b2";

function getWeather(lat, lon) {
  var url = "https://api.openweathermap.org/data/2.5/weather?lat=" + lat +
            "&lon=" + lon + "&units=metric&appid=" + apiKey;

  fetch(url)
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var temp = Math.round(data.main.temp);
      var city = data.name;
      var desc = data.weather[0].description;
      var icon = "https://openweathermap.org/img/wn/" + data.weather[0].icon + "@2x.png";

      document.getElementById("weatherWidget").innerHTML =
        '<img src="' + icon + '" style="width:40px; vertical-align:middle;"> ' +
        '<strong>' + temp + '°C</strong> – ' + desc + '<br>' +
        '<small>📍 ' + city + '</small>';
    })
    .catch(function() {
      document.getElementById("weatherWidget").textContent = "Unable to load weather 🌧️";
    });
}

if ("geolocation" in navigator) {
  navigator.geolocation.getCurrentPosition(
    function(pos) {
      getWeather(pos.coords.latitude, pos.coords.longitude);
    },
    function() {
      document.getElementById("weatherWidget").textContent = "Location blocked 🚫";
    }
  );
} else {
  document.getElementById("weatherWidget").textContent = "Geolocation not supported ❌";
}
