var _SeatBookView = null;

app.controller('SeatBookViewCtrl', function ($scope, $http) {

	_SeatBookView = $scope;

	$scope.SeatBookList = [];
	$scope.FloorList = [];
	$scope.FloorId = "0";

	$scope.GetAllFloor = function () {

		$http.post("/UserAccess/GetAllFloorList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.FloorList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllFloor();

	$scope.LoadSeatBookViewList = function () {

		$http({
			method: "POST",
			url: "/SeatBook/ViewSeatBookList",
			params: {}
		}).then(function mySuccess(response) {

			var mData = response.data.returnVal;

			mData = JSON.parse(mData);

			$scope.SeatBookList = mData.Table;
			
		}, function myError(response) {
			alert(response.statusText)
		});

	}

	$scope.LoadSeatBookViewList();

	$scope.BookSeat = function (vFloorId) {

		var mFloorId = vFloorId;

		window.location.href = "/Floor/EditMapFloor?id=" + mFloorId + "&vType=BS";

		return false;
	}

	$scope.IsWorkFromHome = function () {

		if (confirm("在宅勤務登録しますか？")) {

			var mIsWFH = "1";

			$http({
				method: "POST",
				url: "/SeatBook/SaveWFH",
				params: { IsWFH: mIsWFH }
			}).then(function mySuccess(response) {

				swal({
					title: "SUCCESS!",
					text: "正常に完了しました。",
					type: "success",
					confirmButtonText: "OK"
				},
					function (isConfirm) {
						window.location.href = '/SeatBook/Index';
					});
			}, function myError(response) {
				alert(response.statusText)
			});
		}

		return false;
	}

	$scope.CheckOutSeat = function () {

		if (confirm("退席・勤務終了処理しますか?")) {

			$http({
				method: "POST",
				url: "/SeatBook/CheckOut",
				params: {}
			}).then(function mySuccess(response) {

				swal({
					title: "SUCCESS!",
					text: "正常に完了しました。",
					type: "success",
					confirmButtonText: "OK"
				},
					function (isConfirm) {
						window.location.href = '/SeatBook/Index';
					});
			}, function myError(response) {
				alert(response.statusText)
			});
		}

		return false;
	}

	$scope.IsWFH = "0";
	$scope.IsCheckout = "0";

	$scope.SeatBookCheckRights = function () {

		$http({
			method: "POST",
			url: "/SeatBook/SeatBookCheckRights",
			params: {}
		}).then(function mySuccess(response) {
			
			response = response.data.returnVal;
			response = JSON.parse(response);

			$scope.IsWFH = response.Table[0].IsWFH;
			$scope.IsCheckout = response.Table[0].IsCheckout;
			$scope.IsWorking = response.Table[0].IsWorking;
			
		}, function myError(response) {
			alert(response.statusText);
		});
	}

	$scope.SeatBookCheckRights();


});