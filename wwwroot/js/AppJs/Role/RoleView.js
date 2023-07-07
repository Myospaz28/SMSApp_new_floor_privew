
app.controller('RoleViewCtrl', function ($scope, $http) {

	$scope.RoleList = [];

	$scope.LoadRoleViewList = function () {
		
		$http.post("/Roles/ViewRolesList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.RoleList = mData.Table;

		}, function (data) {
		});
	}

	$scope.LoadRoleViewList();

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId;
	}
});
