var _ControllerMapForm = null;

app.controller('ControllerMapFormCtrl', function ($scope, $http) {

	_ControllerMapForm = $scope;

	$scope.FloorList = [];

	$scope.GetAllFloor = function () {

		$http.post("/ControllerMap/GetAllFloor",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.FloorList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllFloor();

	$scope.FormFloorList = [];

	var mFloorListJson = $("#txtFloorListJson").val();

	if (mFloorListJson != undefined && mFloorListJson != "" && mFloorListJson != null) {
		$scope.FormFloorList = JSON.parse(mFloorListJson);
	}

	$scope.AddFloor = function () {

		var mFloorId = $("#ddlFloor option:selected").val();
		var mFloorName = $("#ddlFloor option:selected").text();
		var mIsUserAdded = false;

		if (mFloorId == "0") {
			alert("ユーザを選択してください。");
			return false;
		}

		if ($scope.FormFloorList != undefined && $scope.FormFloorList != null) {

			for (var i = 0; i < $scope.FormFloorList.length; i++) {

				if ($scope.FormFloorList[i].FloorId == mFloorId) {

					mIsUserAdded = true;
					alert("このユーザは既に追加されています.");
					break;

				}
			}
		}

		if (mIsUserAdded) {
			return false;
		}

		var mRowId = $scope.FormFloorList.filter(function (entry) {
			return entry.IsType !== 'D';
		}).length + 1;

		$scope.FormFloorList.push({
			RowId: mRowId,
			FloorId: mFloorId,
			FloorName: mFloorName,
			IsType: "N"
		});
	}

	$scope.RemoveUser = function (vRowId) {

		for (var i = 0; i < $scope.FormFloorList.length; i++) {

			if ($scope.FormFloorList[i].RowId == vRowId) {
				$scope.FormFloorList[i].IsType = "D";

				return;
			}

		}
	}

});

function SaveControllerMap() {

	if (_ControllerMapForm.FormFloorList == null || typeof (_ControllerMapForm.FormFloorList) == "undefined"
		|| _ControllerMapForm.FormFloorList.length == 0) {
		alert("部門管理者を選択");
		return false;
	}

	$("#txtFloorListJson").val(JSON.stringify(_ControllerMapForm.FormFloorList));

	return true;
}