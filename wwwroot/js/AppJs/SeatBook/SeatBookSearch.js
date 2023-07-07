var _SeatBookSearch = null;

app.controller('SeatBookSearchCtrl', function ($scope, $http, $compile) {

	_SeatBookSearch = $scope;

	$scope.currentPage = 1;
	$scope.pageSize = 10;

	$scope.SeatBookSearchLst = [];

	$scope.DeptId = "0";
	$scope.Search = "";

	$scope.SeatBookSearchList = function () {

		var mSrchType = $("input[name='rdSearch']:checked").val();

		var mLastName = $(".txtLastName").val();
		var mFirstName = $(".txtFirstName").val();

		var mFloor = $('#ddlFloor').val();

		if (mFloor != null && mFloor != "") {
			mFloor = mFloor.toString();
		}

		var mDeptId = $('#ddlDept option:selected').val();

		if (mDeptId != null && mDeptId != "") {
			mDeptId = mDeptId.toString();

			mDeptId = mDeptId.split(":")[1];
		}

		$http({
			method: "POST",
			url: "/SeatBook/SeatSearchList",
			params: {
				vLastName: mLastName,
				vFirstName: mFirstName,
				vFloorId: mFloor,
				vDeptId: mDeptId,
				vSrchType: mSrchType
			}
		}).then(function mySuccess(response) {

			var mData = JSON.parse(response.data);

			$scope.SeatBookSearchLst = mData.Table;

		}, function myError(response) {
			alert(response.statusText);
		});
	}

	$scope.OnSeatBookSearchChange = function () {

		var mSrchType = $("input[name='rdSearch']:checked").val();

		if (mSrchType == "Name") {
			$scope.FloorId = "0";
			$("#select2-ddlFloor-container").text("--Select--");

			$scope.DeptId = "0";
			$('#ddlDept').select2();
			$("#select2-ddlDept-container").text("--Select--");
		}
		else if (mSrchType == "FLR") {

			$(".txtLastName").val("");
			$(".txtFirstName").val("");

			$scope.DeptId = "0";
			$('#ddlDept').select2();
			$("#select2-ddlDept-container").text("--Select--");

		}
		else if (mSrchType == "DPT") {

			$(".txtLastName").val("");
			$(".txtFirstName").val("");

			$scope.FloorId = "0";
			$("#select2-ddlFloor-container").text("--Select--");
		}

		$scope.SeatBookSearchLst = [];
	}

	$scope.ResetSeatBookSearchChange = function () {

		window.location.reload();

		//$("input[name='rdSearch']").attr("checked", false);

		//$(".txtLastName").val("");
		//$(".txtFirstName").val("");

		//$("#rdSearchFlR").prop("checked", true);
		//$("#txtLastName").attr("readonly", "readonly");
		//$("#txtFirstName").attr("readonly", "readonly");
		//$("#ddlFloor").select2({ disabled: false });
		//$("#ddlDept").select2({ disabled: true });

		//$scope.FloorId = "0";
		//$("#select2-ddlFloor-container").text("--Select--");

		//$scope.DeptId = "0";
		//$("#select2-ddlDept-container").text("--Select--");
		//$scope.SeatBookSearchLst = [];

		//$scope.DisabledOthField();
	}

	$scope.ViewSeat = function (vFloorId, vFloorMapId) {

		/*window.location.href = "/Floor/EditMapFloor?id=" + vFloorId + "&FloorMapId=" + vFloorMapId + "&vType=Srch";*/
		//alert(1);

		var mUrl = "/Floor/OpenSeatSearch?id=" + vFloorId + "&FloorMapId=" + vFloorMapId + "&vType=Srch";
		var mDiv = $("#dvSearchModal");

		mDiv.modal('show');

		//var mdvProc = mDiv.find(".dvProc");
		//var mdvData = mDiv.find(".dvData");
		//mdvProc.show();
		//mdvData.hide();

		$.get(mUrl, {},
			function (data) {

				//mdvProc.hide();
				//mdvData.show();

				mDiv.html($compile(data)($scope));
				$scope.$apply();
			});

		return false;
	}

	$scope.OpenSeat = function (vFloorId, vFloorMapId) {
		window.open("/Floor/EditMapFloor?id=" + vFloorId + "&FloorMapId=" + vFloorMapId + "&vType=Srch", "New", "height=1000,width=1000");
	}

	$scope.FloorId = "0";

	$scope.GetAllFloor = function () {

		var mData = { 'vType': 'SeatSrch' };

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

	$scope.GetAllDepartment = function () {

		$http.post("/User/GetAllDepartment",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.DeptList = mData.Table;


		}, function (data) {
		});
	}

	$scope.GetAllDepartment();

	$scope.DisabledOthField = function () {

		var mSrchType = $("input[name='rdSearch']:checked").val();

		if (mSrchType == "FLR") {

			$("#txtLastName").val("");
			$("#txtFirstName").val("");

			$("#txtLastName").attr("readonly", "readonly");
			$("#txtFirstName").attr("readonly", "readonly");

			$("#ddlFloor").select2({ disabled: false });
			$("#ddlDept").select2({ disabled: true });

			$scope.DeptId = "0";
			$("#select2-ddlDept-container").text("--Select--");

			$scope.FloorId = "0";
			$("#select2-ddlFloor-container").text("--Select--");

		}
		else if (mSrchType == "Name") {

			$("#txtLastName").removeAttr("readonly");
			$("#txtFirstName").removeAttr("readonly");

			$("#ddlFloor").select2({ disabled: true });
			$("#ddlDept").select2({ disabled: true });

			$("#txtLastName").val("");
			$("#txtFirstName").val("");

			$scope.FloorId = "0";
			$("#select2-ddlFloor-container").text("--Select--");

			$scope.DeptId = "0";
			$("#select2-ddlDept-container").text("--Select--");

		}
		else if (mSrchType == "DPT") {

			$("#txtLastName").attr("readonly", "readonly");
			$("#txtFirstName").attr("readonly", "readonly");

			$("#ddlFloor").select2({ disabled: true });
			$("#ddlDept").select2({ disabled: false });

			$("#txtLastName").val("");
			$("#txtFirstName").val("");

			$scope.FloorId = "0";
			$("#select2-ddlFloor-container").text("--Select--");

			$scope.DeptId = "0";
			$("#select2-ddlDept-container").text("--Select--");
		}
	}

});

function OnUserSuccess() {
	swal({
		title: "SUCCESS!",
		text: "正常に完了しました。",
		type: "success",
		confirmButtonText: "OK"
	},
		function (isConfirm) {
			window.location.href = '/Floor/Index';
		});
}

function RedirectBack() {

	window.location.href = '/User/Index';

	return false;
}

$(document).ready(function () {
	$("#rdSearchFlR").prop("checked", true);

	_SeatBookSearch.DisabledOthField();
});


var _FloorMapForm = null;
var mDeptId;

app.controller('FloorMapFormCtrl', function ($scope, $http) {

	_FloorMapForm = $scope;

	$scope.FloorAdminList = [];
	$scope.FloorAdminId = "0";

	$scope.pageSize = 10;
	$scope.currentPage = 1;

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

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId;
	}

	var mDeptId = $("#txtDeptId").val();

	if (mDeptId != undefined & mDeptId != null) {
		$scope.DeptId = mDeptId;
	}

	$scope.GetAllDepartment = function () {

		$http.post("/User/GetAllDepartment",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.DeptList = mData.Table;

		}, function (data) {
		});
	}

	$scope.GetAllDepartment();

	$scope.AllWFHUsersUnderHM = [];

	$scope.GetAllWFHUsersUnderHM = function () {

		var mData = { 'vFloorId': mFloorId };

		$http({
			method: "POST",
			url: "/Floor/GetAllWFHUserUnderHM",
			params: mData
		}).then(function mySuccess(response) {

			var mData = JSON.parse(response.data);

			$scope.AllWFHUsersUnderHM = mData.Table;

			$("#dvWFHUser").modal('show');

		}, function myError(response) {
			alert(response.statusText);
		});
	}

	$scope.LoadSearchData = function () {

		var mFloorMapJSON = $("#txtFloorJSON").val();

		if (mFloorMapJSON != undefined && mFloorMapJSON != null) {

			mFloorMapJSON = JSON.parse(mFloorMapJSON);

			for (var i = 0; i < mFloorMapJSON.length; i++) {

				var elemDiv = document.createElement('div');
				var elemSpan = document.createElement('span');

				elemDiv.style.cssText = 'position:absolute;width:' + mFloorMapJSON[i].width + 'px;height:' + mFloorMapJSON[i].height + 'px;background:' + mFloorMapJSON[i].BGColor + ';cursor: pointer;';
				elemDiv.style.left = mFloorMapJSON[i].CurrentX + "px";
				elemDiv.style.top = mFloorMapJSON[i].CurrentY + "px";
				elemSpan.innerHTML = mFloorMapJSON[i].UserDisplay;
				elemSpan.style.cssText = 'position: absolute;width: max-content;background:' + mFloorMapJSON[i].BGColor + ';font-weight: bolder;color:black;font-size:' + mFloorMapJSON[i].UsernameFontsize + 'px';

				elemDiv.id = "dv_" + i.toString();

				var mIsCreatedUsr = (mFloorMapJSON[i].CreatedBy != "0" && mFloorMapJSON[i].CreatedBy == mCurrUserId) ? "Y" : "N";
				var mName = mFloorMapJSON[i].LNKanji + ' ' + mFloorMapJSON[i].FNKanji;

				if (mFloorMapJSON[i].BGColor != "rgba(0, 0, 255, 0.25)") {
					elemDiv.setAttribute("onclick", "showPopup('" + i.toString() + "','" + mName + "','" + mFloorMapJSON[i].UserTitle + "','" + mFloorMapJSON[i].ProfilePhotoPath + "','" + mFloorMapJSON[i].DeptName + "')");
				}

				elemDiv.appendChild(elemSpan);

				$('.dvControls').append(elemDiv);
			}
		}
	}

	$scope.CloseDialog = function () {
		var mDiv = $("#dvSearchModal");
		mDiv.modal('hide');
	};

});

function SaveFloorMap() {
	$("#txtDeptId").val(mDeptId);
	return true;
}

function OnDeptSel() {
	mDeptId = $("#ddlDept option:selected").val().split(':')[1];
}

function BookSeat(vId) {

	var mFloorMapJSON = $("#txtFloorJSON").val();

	if (mFloorMapJSON != undefined && mFloorMapJSON != null) {

		mFloorMapJSON = JSON.parse(mFloorMapJSON);

		for (var i = 0; i < mFloorMapJSON.length; i++) {

			if (mFloorMapJSON[i].Id == vId) {

				//var mName = (mFloorMapJSON[i].UserDisplay != undefined && mFloorMapJSON[i].UserDisplay != "")
				//    ? mFloorMapJSON[i].UserDisplay : mFloorMapJSON[i].LNName;

				var mName = mFloorMapJSON[i].LNKanji + ' ' + mFloorMapJSON[i].FNKanji;

				if (mName != "" && mName != undefined) {
					mName = mFloorMapJSON[i].DeptName + "<br/>" + mFloorMapJSON[i].UserTitle + "<br/>" + mName;
				}

				$("#spUserName").html(mName);

				if (mFloorMapJSON[i].ProfilePhotoPath != "" && mFloorMapJSON[i].ProfilePhotoPath != undefined) {
					var mPhoto = mFloorMapJSON[i].ProfilePhotoPath;

					mPhoto = mPhoto.replace("~", "..");

					$("#spImgUserDtls").attr("src", mPhoto);
				}

				$("#spSeatId").text(mFloorMapJSON[i].SeatID);
				$("#spSeatDetails").text(mFloorMapJSON[i].SeatDetails);
				$("#txtBookFloorId").val(mFloorMapJSON[i].FloorId);
				$("#txtBookFloorMapId").val(mFloorMapJSON[i].Id);

				break;
			}
		}

		$("#btnBookSeat").hide();
		$("#btnRelease").hide();

		$("#hdrBookSeat").hide();
		$("#hdrReleaseSeat").hide();

		if (mFloorMapJSON[i].IsBooked != null && mFloorMapJSON[i].IsBooked != undefined && mFloorMapJSON[i].IsBooked == "1") {
			$("#btnRelease").show();
			$("#hdrReleaseSeat").show();
		}
		else {
			$("#btnBookSeat").show();
			$("#hdrBookSeat").show();
		}

		$("#dvBookSeat").modal('show');
	}
}

function GetSeatDtls(vId, vWidth, vHeight, vSeatId, vSeatDtls, vCurrentX, vCurrentY) {

	var mWidth = "15";
	var mHeight = "15";

	if (vWidth != "" && vWidth != undefined)
		mWidth = vWidth;

	if (vHeight != "" && vHeight != undefined)
		mHeight = vHeight;

	$("#txtWidth").val(mWidth);
	$("#txtHeight").val(mHeight);

	$("#txtSeatId").val(vSeatId);
	$("#txtSeatDtls").val(vSeatDtls);

	$("#hiddCurrentX").val(vCurrentX);
	$("#hiddCurrentY").val(vCurrentY);

	$("#spCurrentXY").text(vCurrentX + "," + vCurrentY);

	$("#hiddId").val(vId);

	$("#dvChairDtls").modal('show');
}

function showPopup(vIndex, vName, vUserTitle, vProfPicPath, vDeptName) {

	if (vName != "") {
		vName = vDeptName + "<br/>" + vUserTitle + "<br/>" + vName;

		$("#spUserNameDtls").html(vName);

		if (vProfPicPath != "") {
			vProfPicPath = vProfPicPath.replace("~", "..");
			$("#ImgUserDtls").attr("src", vProfPicPath);
		}

		$("#dvUserDtls").modal('show');
	}
}