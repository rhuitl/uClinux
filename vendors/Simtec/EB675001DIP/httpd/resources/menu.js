//determine "class" of browser
var ie4=document.all&&navigator.userAgent.indexOf("Opera")==-1
var ns6=document.getElementById&&!document.all
var ns4=document.layers


function StcMenuIn(e,imgId,imgSrc,which)
{
  if(imgId && document.images && document.images[imgId])
    document.images[imgId].src = imgSrc;//change text higlight

  //if no menu selected forget it
  if(!which)
    return

  //check for requred support
  if (!document.all&&!document.getElementById&&!document.layers)
    return

  if(ie4)
    e=event;

  //remove any sheduled menu closing
  clearhidemenu()

  //obtain the menuobject
  menuobj=ie4? document.all.popmenu : ns6? document.getElementById("popmenu") : ns4? document.popmenu : ""
  menuobj.thestyle=(ie4||ns6)? menuobj.style : menuobj

  //fill contents
  if (ie4)
    menuobj.innerHTML=which
  else if(ns6){
    menuobj.innerHTML=which
  } else {
    menuobj.document.write('<layer name=gui bgColor=#E6E6E6 width=165 onmouseover="clearhidemenu()" onmouseout="hidemenu()">'+which+'</layer>')
    menuobj.document.close()
  }

  //obtain the width and height of the new menu
  menuobj.contentwidth=(ie4||ns6)? menuobj.offsetWidth : menuobj.document.gui.document.width
  menuobj.contentheight=(ie4||ns6)? menuobj.offsetHeight : menuobj.document.gui.document.height

  var eventS=e.srcElement? e.srcElement : e.target
//  var eventPt = { x: 0, y: 0 };
//  eventPt.x=ie4? event.clientX : ns6? e.clientX : e.x
//  eventPt.y=ie4? event.clientY : ns6? e.clientY : e.x
  pagePt=getPageXY(eventS)
  pagePt.y=pagePt.y+eventS.offsetHeight


  //Find out how close the mouse is to the corner of the window
  var rightedge=(ie4? document.body.clientWidth : window.innerWidth ) - pagePt.x
  var bottomedge=(ie4? document.body.clientHeight : window.innerHeight ) - pagePt.y

  //x and y move position allowing for scroll offsets
//  pagePt.x=pagePt.x + (ie4? document.body.scrollLeft : ns6? window.pageXOffset : 0 )
//  pagePt.y= pagePt.y + (ie4? document.body.scrollTop : ns6? window.pageYOffset : 0 )

  //if the horizontal distance isn't enough to accomodate the width of the context menu
  //move the horizontal position of the menu to the left by it's width
  if (rightedge < menuobj.contentwidth)
    pagePt.x=pagePt.x - menuobj.contentwidth

  //same concept with the vertical position
  if (bottomedge < menuobj.contentheight)
    pagePt.y=pagePt.y - menuobj.contentheight

  if(ie4)
  {
    menuobj.thestyle.pixelLeft=pagePt.x
    menuobj.thestyle.pixelTop=pagePt.y
  }
  else if (ns6){
    menuobj.thestyle.left=pagePt.x + "px";
    menuobj.thestyle.top=pagePt.y + "px";
  }else{
    menuobj.thestyle.left=pagePt.x ;
    menuobj.thestyle.top=pagePt.y ;
  }
  menuobj.thestyle.visibility="visible"

  return false
}

function StcMenuOut(imgId,imgSrc)
{
  if(imgId && document.images && document.images[imgId])
    document.images[imgId].src = imgSrc;//change text higlight

  if (ie4||ns6||ns4)
    delayhide=setTimeout("hidemenu()",500)

}

function hidemenu(){
  if (window.menuobj)
    menuobj.thestyle.visibility=(ie4||ns6)? "hidden" : "hide"
}

function dynamichide(e){
  if (ie4&&!menuobj.contains(e.toElement))
    hidemenu()
  else if (ns6&&e.currentTarget!= e.relatedTarget&& !contains_ns6(e.currentTarget, e.relatedTarget))
    hidemenu()
}

function clearhidemenu(){
  if (window.delayhide)
    clearTimeout(delayhide)
}

function highlightmenu(e,state){
  if (document.all)
    source_el=event.srcElement
  else if (document.getElementById)
    source_el=e.target
  if (source_el.className=="menuitems"){
    source_el.id=(state=="on")? "mouseoverstyle" : ""
  }
  else{
    while(source_el.id!="popmenu"){
      source_el=document.getElementById? source_el.parentNode : source_el.parentElement
      if (source_el.className=="menuitems"){
        source_el.id=(state=="on")? "mouseoverstyle" : ""
      }
    }
  }
}

//background click hides menu
if (ie4||ns6)
  document.onclick=hidemenu
