
app.controller('FloorViewCtrl', function ($scope, $http) {

	$scope.FloorList = [];
	$scope.currentPage = 1;
	$scope.pageSize = 10;

	$scope.IsActive = "1";

	$scope.LoadFloorViewList = function (vType) {

		var mData = { 'vIsActive': vType };

		$http({
			method: "POST",
			url: "/Floor/ViewFloorList",
			params: mData
		}).then(function mySuccess(response) {

			var mData = JSON.parse(response.data);

			$scope.FloorList = mData.Table;

		}, function myError(response) {
			alert(response.statusText);
		});
	}

	$scope.LoadFloorViewList("1");

	$scope.pageChangeHandler = function (num) {
		console.log('meals page changed to ' + num);
	};

	$scope.RedirectFloorToEdit = function (vFloorId) {

		window.location.href = "/Floor/EditFloor/" + vFloorId;
		return false;
	}

	$scope.RedirectToMapFloorEdit = function (vFloorId, vFloorMapId) {

		window.location.href = "/Floor/EditMapFloor?id=" + vFloorId + "&FloorMapId=" + vFloorMapId + "&vType=Map";
		return false;
	}

});
