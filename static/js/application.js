$(document).ready(function() {

  $( function() {
    $( "#confirm-delete" ).dialog({
      resizable: false,
      height: "auto",
      width: 400,
      modal: true,
      buttons: {
        "Delete all items": function() {
          $( this ).dialog( "close" );
        },
        Cancel: function() {
          $( this ).dialog( "close" );
        }
      }
    });

  $('#confirm-delete-button').on('click', function() {
	  var message = $("<div id='confirm-delete' title='Delete Entry?'><p><span class='ui-icon ui-icon-alert' style='float:left; margin:12px 12px 20px 0;'></span>These items will be permanently deleted and cannot be recovered. Are you sure?</p></div>");
  	$('body').append(message);
  });


} );
