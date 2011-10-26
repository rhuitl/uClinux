// Document JavaScript
// Captura del teclat
if(document.addEventListener){ // Codi Mozilla
  document.addEventListener("keydown",keyCapt,false);
  }
else{	// Codi IE
    document.attachEvent("onkeydown",keyCapt);
}

function keyCapt(e){
	if(window.event){
    teclap = e.keyCode
  }else{			// Codi Mozilla
    teclap = e.which
  }
  switch(teclap){
	case 37:	// Fletxa esq
		var adre = '/cgi-bin/teclap.cgi?tecla=B';
		break;
	/*case 40:	// Fletxa avall
		var adre = '/cgi-bin/teclap.cgi?tecla=' + String.fromCharCode(e.which);
		break;
	case 39:	// Fletxa dreta
		var adre = '/cgi-bin/teclap.cgi?tecla=' + String.fromCharCode(e.which);
		break;*/
	case 13:	// Retorn o lletra E
	case 69:
		window.status = 'E';
		var adre = '/cgi-bin/teclap.cgi?tecla=E';
		break;
	case 70:	// Tecla premuda: lletra F
		window.status = 'F';
		var adre = '/cgi-bin/teclap.cgi?tecla=F';
		break;
	case 71:	// Tecla premuda: lletra F1
		window.status = 'F1';
		var adre = '/cgi-bin/teclap.cgi?tecla=G';
		break;
	case 72:	// Tecla premuda: lletra F2
		window.status = 'F2';
		var adre = '/cgi-bin/teclap.cgi?tecla=H';
		break;
	case 74:	// Tecla premuda: lletra F3
		window.status = 'F3';
		var adre = '/cgi-bin/teclap.cgi?tecla=J';
		break;
	case 75:	// Tecla premuda: lletra F4
		window.status = 'F4';
		var adre = '/cgi-bin/teclap.cgi?tecla=K';
		break;
	case 27:
	case 76:	// Tecla premuda: lletra F5
		window.status = 'F5';
		var adre = '/cgi-bin/teclap.cgi?tecla=L';
		break;
	case 67:	// Tecla premuda: lletra C
		window.status = 'C';
		var adre = '/cgi-bin/teclap.cgi?tecla=C';
		break;
	case 48:
	case 96:	// Tecla premuda: 0
		window.status = '0';
		var adre = '/cgi-bin/teclap.cgi?tecla=0';
		break;
	case 49:
	case 97:	// Tecla premuda: 1
		window.status = '1';
		var adre = '/cgi-bin/teclap.cgi?tecla=1';
		break;
	case 50:
	case 98:	// Tecla premuda: 2
		window.status = '2';
		var adre = '/cgi-bin/teclap.cgi?tecla=2';
		break;
	case 51:
	case 99:	// Tecla premuda: 3
		window.status = '3';
		var adre = '/cgi-bin/teclap.cgi?tecla=3';
		break;
	case 52:
	case 100:	// Tecla premuda: 4
		window.status = '4';
		var adre = '/cgi-bin/teclap.cgi?tecla=4';
		break;
	case 53:
	case 101:	// Tecla premuda: 5
		window.status = '5';
		var adre = '/cgi-bin/teclap.cgi?tecla=5';
		break;
	case 54:
	case 102:	// Tecla premuda: 6
		window.status = '6';
		var adre = '/cgi-bin/teclap.cgi?tecla=6';
		break;
	case 55:
	case 103:	// Tecla premuda: 7
		window.status = '7';
		var adre = '/cgi-bin/teclap.cgi?tecla=7';
		break;
	case 56:
	case 104:	// Tecla premuda: 8
		window.status = '8';
		var adre = '/cgi-bin/teclap.cgi?tecla=8';
		break;
	case 57:
	case 105:	// Tecla premuda: 9
		window.status = '9';
		var adre = '/cgi-bin/teclap.cgi?tecla=9';
		break;
	case 61:	// La tecla +
	case 107:
	case 187:
		window.status = '+';
		var adre = '/cgi-bin/teclap.cgi?tecla=P';
		break;
	case 109:	// La tecla -
		window.status = '-';
		var adre = '/cgi-bin/teclap.cgi?tecla=-';
		break;
	case 190:	// Tecla premuda: El punt
		window.status = '.';
		var adre = '/cgi-bin/teclap.cgi?tecla=.';
		break;
	default:
		window.status = teclap;
		var adre = '/cgi-bin/teclap.cgi?tecla=' + String.fromCharCode(teclap);
    }
	cridarAsincronament(adre, 'display');
}


var secs
var timerID = null
var delay = 500

function Temporitzador(){
    secs = 1
    IniciaTemporitzador()
}

function IniciaTemporitzador(){
    if (secs==0){
	cridarAsincronament('/cgi-bin/teclap.cgi?tecla=R', 'display')
	Temporitzador()
    } else {
        secs = secs - 1
        timerID = self.setTimeout("IniciaTemporitzador()", delay)
    }
}

// Funcions AJAX

// Tot es correcte i ha arribat el moment de posar la informació requerida
// al lloc demanat (contenidor) a la plana xhtml

function cargarpagina(pagina_requerida, id_contenidor){
    if (pagina_requerida.readyState == 4 && (pagina_requerida.status == 200 || window.location.href.indexOf ("http") == - 1))
    document.getElementById(id_contenidor).innerHTML = pagina_requerida.responseText;
}

function cridarAsincronament(url, id_contenidor){

    var pagina_requerida = false;
		var url = url + new Date().getTime()	// Per evitar problemes de chache a IE

    if(window.XMLHttpRequest){
        // Si es Mozilla, Safari etc
        pagina_requerida = new XMLHttpRequest ();
    } else if(window.ActiveXObject){
        // pero si es IE
        try{
            pagina_requerida = new ActiveXObject("Msxml2.XMLHTTP");
        }
	catch (e){
        	// en cas que sigui una versio antiga
        	try{
            		pagina_requerida = new ActiveXObject("Microsoft.XMLHTTP");
        	}
		catch (e){
       		}
        }
    }
    else
    return false;
    pagina_requerida.onreadystatechange = function(){
        // funció de resposta
        cargarpagina(pagina_requerida, id_contenidor);
    }
    pagina_requerida.open ('GET', url, true);
    pagina_requerida.send (null);
}

