var _UserAccessForm = null;
var mFlrId;

app.controller('UserAccessFormCtrl', function ($scope, $http) {

	_UserAccessForm = $scope;

	$scope.UserAccessList = [];
	$scope.UserId = "0";

	$scope.GetAllUsers = function () {

		$http.post("/UserAccess/GetAllUsersList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.UserAccessList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllUsers();

	$scope.FloorList = [];
	$scope.FloorId = "0";

	var mFloorId = $("#ddlFloor option:selected").val();

	if (mFloorId != "" && mFloorId != undefined && mFloorId != "--Select--") {
		$scope.FloorId = mFloorId;
	}

	$scope.GetAllFloor = function () {

		var mData = { 'vType': 'UsrAccess' };

		$http({
			method: "POST",
			url: "/UserAccess/GetAllFloorList",
			params: mData
		}).then(function mySuccess(response) {

			var mData = JSON.parse(response.data);

			$scope.FloorList = mData.Table;

		}, function myError(response) {
			alert(response.statusText);
		});

	}

	$scope.GetAllFloor();

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId;
	}

	$scope.AllMapUsers = [];
	$scope.UserId = "0";

	var mAllMapUsers = $("#txtUserJSON").val();

	if (mAllMapUsers != undefined && mAllMapUsers != "" && mAllMapUsers != null) {
		$scope.AllMapUsers = JSON.parse(mAllMapUsers);
	}

	$scope.AddUsersList = function () {

		var mUserId = $("#ddlUser option:selected").val().split(':')[1];
		var mUserName = $("#ddlUser option:selected").text();
		var mIsUserAdded = false;

		if (mUserId == "0") {
			alert("Please select User !!!");
			return false;
		}

		if ($scope.AllMapUsers != undefined && $scope.AllMapUsers != null) {

			for (var i = 0; i < $scope.AllMapUsers.length; i++) {

				if ($scope.AllMapUsers[i].UserId == mUserId) {

					mIsUserAdded = true;
					alert("既に登録済みのユーザです。");
					break;

				}
			}
		}

		if (mIsUserAdded) {
			return false;
		}

		var mRowId = $scope.AllMapUsers.filter(function (entry) {
			return entry.IsType !== 'D';
		}).length + 1;

		$scope.AllMapUsers.push({
			RowId: mRowId,
			Id: "0",
			UserId: mUserId,
			UserName: mUserName,
			Select: "UVw",
			IsType: "N"
		});
	}

	$scope.RemoveUser = function (vRowId) {

		for (var i = 0; i < $scope.AllMapUsers.length; i++) {

			if ($scope.AllMapUsers[i].RowId == vRowId) {
				$scope.AllMapUsers[i].IsType = "D";
				break;
			}
		}

	}

});

function SaveUserAccess() {

	var mtxtUserAccessId = $("#txtUserAccessId").val();

	if ((_UserAccessForm.FloorId == undefined || _UserAccessForm.FloorId == "" || _UserAccessForm.FloorId == "0") &&
		(mtxtUserAccessId == undefined || mtxtUserAccessId == "" || mtxtUserAccessId == null)
	) {
		alert("Please select フロア !!");
		return false;
	}

	if (_UserAccessForm.AllMapUsers == undefined || _UserAccessForm.AllMapUsers == "") {
		alert("Please Add ユーザの選択 !!");
		return false;
	}

	if (_UserAccessForm.FloorId != undefined && _UserAccessForm.FloorId != "" && _UserAccessForm.FloorId != "0") {
		$("#txtFloorId").val(_UserAccessForm.FloorId);
	}

	if (_UserAccessForm.AllMapUsers != undefined && _UserAccessForm.AllMapUsers != "") {
		$("#txtUserJSON").val(JSON.stringify(_UserAccessForm.AllMapUsers));
	}

	return true;
}

function OnFloorSel() {
	mFlrId = $("#ddlFloor option:selected").val().split(':')[1];
}

//function GetUserData() {

//	$(".ddlUsers").select2({
//		ajax: {
//			url: "Enquiry/FillEnquiryListFor",
//			dataType: 'json',
//			delay: 0,
//			data: function (params) {
//				return {
//					q: params.term, // search term
//					page: params.page
//				};
//			},
//			processResults: function (data, params) {
//				data = JSON.parse(data);
//				return {
//					results: data,
//				};
//			},
//			cache: true
//		},
//		escapeMarkup: function (markup) {
//			return markup;
//		}, // let our custom formatter work
//		minimumInputLength: 1
//	});
//}