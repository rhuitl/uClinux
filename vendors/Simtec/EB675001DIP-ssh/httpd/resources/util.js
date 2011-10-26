//array for menu links
var linkset=new Array()

linkset[0]='<div class="menuitems"><a href="/home/welcome.html">Welcome</a></div>'

linkset[1]='<div class="menuitems"><a href="/products/">Overview</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/systems.html">Complete Systems</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/boards.html">System Boards</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/components.html">System components</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/design.html">Design components</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/software.html">Software</a></div>'
linkset[1]+='<div class="menuitems"><a href="/products/all.html">All Products</a></div>'


linkset[2]='<div class="menuitems"><a href="/services/">Overview</a></div>'
linkset[2]+='<div class="menuitems"><a href="/services/complete.html">Complete Solutions</a></div>'
linkset[2]+='<div class="menuitems"><a href="/services/hardware.html">Hardware Services</a></div>'
linkset[2]+='<div class="menuitems"><a href="/services/manuf.html">Manufacturing</a></div>'
linkset[2]+='<div class="menuitems"><a href="/services/software.html">Software Services</a></div>'

linkset[3]='<div class="menuitems"><a href="/support/">Overview</a></div>'
linkset[3]+='<div class="menuitems"><a href="/support/bronze.html">Bronze</a></div>'
linkset[3]+='<div class="menuitems"><a href="/support/silver.html">Silver</a></div>'
linkset[3]+='<div class="menuitems"><a href="/support/gold.html">Gold</a></div>'
linkset[3]+='<div class="menuitems"><a href="/support/platinum.html">Platinum</a></div>'
linkset[3]+='<div class="menuitems"><a href="/support/resources.html">Resources</a></div>'
linkset[3]+='<div class="menuitems"><a href="https://secure.simtec.co.uk/cgi-bin/account.cgi">User Account</a></div>'


linkset[4]='<div class="menuitems"><a href="/company/">Overview</a></div>'
linkset[4]+='<div class="menuitems"><a href="/company/about.html">About Simtec</a></div>'
linkset[4]+='<div class="menuitems"><a href="/company/contact.html">Contact Details</a></div>'
linkset[4]+='<div class="menuitems"><a href="/company/ordering.html">How to order</a></div>'
linkset[4]+='<div class="menuitems"><a href="/partners/">Partners</a></div>'
linkset[4]+='<div class="menuitems"><a href="/company/customers.html">Customers</a></div>'
linkset[4]+='<div class="menuitems"><a href="/company/legal.html">Legal</a></div>'



function getPageXY(elm)
{
  var point = { x: 0, y: 0 };
  while (elm)
  {
    point.x += elm.offsetLeft;
    point.y += elm.offsetTop;
    elm = elm.offsetParent;
  }
  return point;
}


//Determines if 1 element in contained in another
function contains_ns6(a, b) {
  if(b)
    while (b.parentNode)
      if ((b = b.parentNode) == a)
        return true;
  return false;
}

//changes specified image
function StcImgChange(imgId,imgSrc)
{
  if(document.images && document.images[imgId])
    document.images[imgId].src = imgSrc;//change text higlight
}

function StcConvert(product,price)
{
  var usrate=1.80656;
  var eurorate=1.42458;
  var yenrate=191.782;
  var properties = 'height=360,width=380,menubar=no,toolbar=no,locationbar=no,personalbar=no,directories=no,statusbar=no,scrollbars=no,resizable=yes';
  var W = window.open("","",properties);
	    W.document.writeln('<html><head>');
	    W.document.writeln('<title>' + product + ' pricing <\/title>');
	    W.document.writeln('<\/head><body bgcolor="white">');
	    W.document.writeln('<h1>' + product + ' pricing<\/h1>');
	    W.document.writeln('<p>The ' + product + ' costs &pound;' + price + ' Sterling (excluding VAT and carriage) see <a href="/company/ordering.html">ordering page<\/a> for details');
	    W.document.writeln('<p>Approximate pricing in other currencies');
	    W.document.writeln('<ul>');
	    W.document.writeln('<li>$' + Math.round(price * usrate) + ' (US Dollar)');
	    W.document.writeln('<li>&euro;' + Math.round(price * eurorate) + ' (Euro)');
	    W.document.writeln('<li>&yen;' + Math.round(price * yenrate) + ' (Japanese Yen)');
	    W.document.writeln('<\/ul>');
	    W.document.writeln('<p>Please note that transactions are in pounds Sterling and the actual amount charged will depend on the exchange rate used by your bank.');
	    W.document.writeln('<form><input type="button" ');
	    W.document.writeln('onClick="window.close()" ');
	    W.document.writeln('value="Close Window">');
	    W.document.writeln('<\/form><\/p>');
	    W.document.writeln('<\/body><\/html>');
}
