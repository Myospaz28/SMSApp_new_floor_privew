
app.controller('ControllerMapViewCtrl', function ($scope, $http) {

	$scope.ControllerMapList = [];
	$scope.currentPage = 1;
	$scope.pageSize = 10;

	$scope.LoadControllerMapViewList = function () {
		
		$http.post("/ControllerMap/ViewControllerMapList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.ControllerMapList = mData.Table;

		}, function (data) {
		});
	}

	$scope.LoadControllerMapViewList();

	$scope.RedirectUserToControllerMap = function (vId) {
		window.location.href = "/ControllerMap/Edit/" + vId;
	}

});
