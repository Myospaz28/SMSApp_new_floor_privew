var app = angular.module('ngApp', ["angularjs-dropdown-multiselect", "angularUtils.directives.dirPagination"]);

app.directive('onFinishRender', function ($timeout) {
	return {
		restrict: 'A',
		link: function (scope, element, attr) {
			ParseDropDownList();
		}
	};
});

app.filter('record', function () {
	return function (array, property, target) {
		if (target && property) {
			target[property] = array;
		}
		return array;
	}
});

app.directive('onTableFinishRender', function ($timeout) {
	return {
		restrict: 'A',
		link: function (scope, element, attr) {
			//$('#tblUserList').dataTable();
			//$('#tblFloorList').dataTable();
		}
	};
});

function ParseDropDownList() {
	$('.ddlSelect2Single').select2();
}