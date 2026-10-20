(()=>{"use strict";
var icon="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PGNpcmNsZSBjeD0iOCIgY3k9IjgiIHI9IjgiLz48L3N2Zz4=";
var logo="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
function renderIcon(){var el=document.createElement("img");el.src=icon;return el}
function renderLogo(){var el=document.createElement("img");el.src=logo;return el}
module.exports={renderIcon:renderIcon,renderLogo:renderLogo};})();
