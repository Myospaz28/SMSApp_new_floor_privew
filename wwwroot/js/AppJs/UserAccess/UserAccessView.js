
app.controller('UserAccessViewCtrl', function ($scope, $http) {

	$scope.UserAccessList = [];
	$scope.currentPage = 1;
	$scope.pageSize = 10;

	$scope.LoadFloorViewList = function () {

		$http.post("/UserAccess/ViewUserAccessList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.UserAccessList = mData.Table;

		}, function (data) {
		});
	}

	$scope.LoadFloorViewList();

	$scope.RedirectUserAccessToEdit = function (vUserAccessId) {
		window.location.href = "/UserAccess/Edit/" + vUserAccessId;
		return false;
	}

	$scope.RedirectToMapFloorEdit = function (vFloorId) {

		window.location.href = "/Floor/EditMapFloor/" + vFloorId;
		return false;
	}

});
