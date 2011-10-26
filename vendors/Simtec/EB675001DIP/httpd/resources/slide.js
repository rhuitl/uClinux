var preload=new Array()
var curindex=0

function img_preload()
{
  for (n=0;n<slide.length;n++)
  {
    preload[n]=new Image()
    preload[n].src="/products/" + slide[n][1] + "/" + slide[n][0]
  }
}

function rotateimage()
{
  tempindex=Math.floor(Math.random()*(slide.length))

  if (curindex==(tempindex)){
    curindex=curindex==0? 1 : curindex-1
  }
  else
    curindex=tempindex

  document.images.defaultimage.src="/products/" + slide[curindex][1] + "/" + slide[curindex][0]

  altercontent(slide[curindex][2])

}

function altercontent(text)
{
  //if IE 4+
  if (document.all)
    dcontent.innerHTML=text;
  else if (document.layers)
  {
    //else if NS 4
    document.ns4dcontent.document.ns4dcontent2.document.write(text);
    document.ns4dcontent.document.ns4dcontent2.document.close();
  }
  else if (document.getElementById)
  {
    //else if NS 6 (supports new DOM)
    rng = document.createRange();
    el = document.getElementById("dcontent");
    rng.setStartBefore(el);
    htmlFrag = rng.createContextualFragment(text);
    while (el.hasChildNodes())
    el.removeChild(el.lastChild);
    el.appendChild(htmlFrag);
  }
}

function slidelink(){
 window.location="/products/" + slide[curindex][1] + "/"
}

img_preload()

rotateimage()

setInterval("rotateimage()",delay)
