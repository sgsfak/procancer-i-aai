function createNewToken(event)
{

    event.preventDefault();

    const XHR = new XMLHttpRequest();

    // Bind the FormData object and the form element
    const FD = new FormData( document.forms[0] );

    // Define what happens on successful data submission
    XHR.addEventListener( "load", function(event) {
        let ta = document.getElementById('token');
        if (ta) {
            document.getElementById('result').style.display = 'block';
            ta.innerText = event.target.responseText;
        }
    } );

    // Define what happens in case of error
    XHR.addEventListener( "error", function( event ) {
      alert( 'Oops! Something went wrong.' );
    } );

    // Set up our request
    XHR.open( "POST", "access_token" );

    // The data sent is what the user provided in the form
    XHR.send( FD );
}

function clipboardNewToken(event) {
    event.preventDefault();
    let ta = document.getElementById('token');
    ta.select()
    document.execCommand("copy");
}