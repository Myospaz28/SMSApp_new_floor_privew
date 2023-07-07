var _FloorForm = null;
var mFlrAdmnId;
var mControllerId;

app.controller('FloorFormCtrl', function ($scope, $http) {

	_FloorForm = $scope;

	$scope.FloorAdminList = [];
	$scope.FloorAdminId = "0";
	$scope.ControllerId = "0";

	var mFloorAdminId = $("#txtFloorAdminId").val();

	if (mFloorAdminId != undefined & mFloorAdminId != null) {
		$scope.FloorAdminId = mFloorAdminId;
	}

	$scope.GetAllFloorAdmin = function () {

		$http.post("/Floor/GetAllFloorAdminList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.FloorAdminList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllFloorAdmin();

	$scope.GetAllController = function () {

		$http.post("/Floor/GetAllControllerList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.ControllerList = mData.Table;

			var mControllerId = $("#txtControllerId").val();

			if (mControllerId != undefined && mControllerId != null && mControllerId != "") {
				$scope.ControllerId = mControllerId;
			}
			else {
				$scope.ControllerId = "0";
			}

		}, function (data) {
		});
	}

	//$scope.GetAllController();

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId;
	}

});

function SaveFloor() {
	$("#txtFloorAdmId").val(_FloorForm.FloorAdminId);
	return true;
}

function OnFlrAdmnSel() {
	mFlrAdmnId = $("#ddlFloorAdmin option:selected").val().split(':')[1];
}

function OnControllerSel() {
	mControllerId = $("#ddlController option:selected").val().split(':')[1];
}
