var _UserForm = null;
var mFlrId;
var mDeptId;
var mHomeMapId;

app.controller('UserFormCtrl', function ($scope, $http) {

	_UserForm = $scope;

	$scope.RoleList = [];
	$scope.FloorList = [];

	$scope.RoleId = "0";
	$scope.FlrId = "0";
	$scope.DeptId = "0";

	var mDeptId = $("#txtDeptId").val();
	var mHomeMapId = $("#txtHomeMapId").val();

	if (mDeptId != undefined && mDeptId != null) {
		$scope.DeptId = mDeptId;
	}
	
	if (mHomeMapId != undefined && mHomeMapId != null) {
		$scope.MapId = mHomeMapId;
	}

	$scope.GetAllRoles = function () {

		$http.post("/User/GetAllRoles",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.RoleList = mData.Table;

		}, function (data) {
		});
	}

	var mFloorId = $("#txtFloor1Id").val();

	if (mFloorId != undefined & mFloorId != null) {
		$scope.FlrId = mFloorId;
	}

	$scope.GetAllFloor = function () {

		$http.post("/User/GetAllFloor",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.FloorList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllDepartment = function () {

		$http.post("/User/GetAllDepartment",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.DeptList = mData.Table;

			var mDeptId = $("#txtDeptId").val();

			if (mDeptId != undefined && mDeptId != null && mDeptId != "") {
				$scope.DeptId = mDeptId;
			}

		}, function (data) {
		});
	}

	$scope.GetAllDepartment();

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId;
	}

	$scope.GetAllHomeMapFloor = function () {

		var mData = { 'vUserId': mUserId };

		$http({
			method: "POST",
			url: "/User/GetAllMapFloor",
			params: mData
		}).then(function mySuccess(response) {

			var mData = JSON.parse(response.data);

			$scope.AllMapFloorList = mData.Table;

		}, function myError(response) {
			alert(response.statusText);
		});

	}

	$scope.GetAllHomeMapFloor();

});

function SaveUser() {

	//$("#txtRoleId").val(_UserForm.RoleId);
	//$("#txtFloor1Id").val(mFlrId);



	$("#txtDeptId").val(mDeptId);
	$("#txtHomeMapId").val(mHomeMapId);

	//if (_UserForm.FormFloorList != undefined && _UserForm.FormFloorList.length > 0) {
	//	$("#txtFloorSelect").val(JSON.stringify(_UserForm.FormFloorList));
	//}

	return true;
}

function OnFlrSel() {
	mFlrId = $("#ddlFloor option:selected").val().split(':')[1];
}

function OnDeptSel() {
	mDeptId = $("#ddlDept option:selected").val().split(':')[1];
}

function OnMapFloorSel() {
	mHomeMapId = $("#ddlHomeMap option:selected").val().split(':')[1];
}