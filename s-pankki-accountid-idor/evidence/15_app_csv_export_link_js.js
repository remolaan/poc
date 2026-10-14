$(function () {
    /* CSV Export button */
    const exportTransactionsLink = '#exportTransactions';

    $('#doExport').on('click', function () {
        /* Fetch the necessary values from the page */
        const accountId = $('.select').val();
        const toDate = $('#toDate').val();
        const fromDate = $('#fromDate').val();

        /* Fetch list from selected account in list */
        const exportAccountId = accountId;

        /* Fetch and parse fromDate for requesting file */
        const exportFromDate = parseDate(fromDate);

        /* Fetch and parse the toDate if it is present, otherwise use fromDate for SOK companies (399) */
        var exportToDate;
        if (typeof toDate === 'undefined') {
            exportToDate = parseDate(fromDate);
        } else {
            exportToDate = parseDate(toDate);
        }

        /* Specify fileType, only CSV available for now */
        const exportFileType = 'sba-CSV';

        const requestUrl = cbs.contextPath +
            '/api/account/transactions/exportRangedTransactions.ds?' +
            'accountId=' + exportAccountId +
            '&fromDate=' + exportFromDate +
            '&toDate=' + exportToDate +
            '&fileType=' + exportFileType;

        startLoading();

        fetch(requestUrl, {
            redirect: 'error',
        })
            .then(resp => resp.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'export.csv';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                stopLoading();
            })
            .catch(() => {
                stopLoading();
                alertDialog(cbs.labels.lbl_error_occurred);
            });
    });

    function startLoading() {
        $(exportTransactionsLink).attr('disabled', 'true');
        $(exportTransactionsLink).addClass('link--disabled');
        waitingDialog();
    }

    function stopLoading() {
        $(exportTransactionsLink).removeAttr('disabled');
        $(exportTransactionsLink).removeClass('link--disabled');
        closeWaitingDialog();
    }

    /* Parses the dates fetched from the form */
    function parseDate(date) {
        var dateArray = date.split('.');

        /* Adds leading 0 before day and month if necessary */
        if (dateArray[0].length === 1) {
            dateArray[0] = '0' + dateArray[0];
        }
        if (dateArray[1].length === 1) {
            dateArray[1] = '0' + dateArray[1];
        }

        return dateArray.join('');
    }
});
