$(function() {

    /* Submit form on change of account number */
    $('#accountId').change(function () {
        $('#padFeesRequestForm').submit();
    });

    /* Redirect to the correct controller request mapping and retrieve year value from select */
    $('#js_getReportButton').click(function() {
        var getReportButton;
        var year;
        var href;

        getReportButton = $('#js_getReportButton');
        year = $('#year').val();
        href = getReportButton.attr('href') + year;
        if (year) {
            openIt2(href);
            return false;
        }
    });
});