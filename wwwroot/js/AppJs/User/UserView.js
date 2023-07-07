
app.controller('UserViewCtrl', function ($scope, $http) {

	$scope.UserList = [];
	$scope.UserListPageDtls = [];

	$scope.currentPage = 1;
	$scope.pageSize = 10;

	$scope.LoadUserViewList = function () {
		
		$http.post("/User/ViewUserList",
			{
			}
		).then(function (resp) {

			var mData = JSON.parse(resp.data);

			$scope.UserList = mData.Table;

		}, function (data) {
		});
    }

    $scope.pageChangeHandler = function (num) {
        console.log('meals page changed to ' + num);
    };

	$scope.LoadUserViewList();

	$scope.RedirectUserToEdit = function (vId) {
		window.location.href = "/User/Edit/" + vId + "?PageType=User";
	}
});

function MyController($scope) {

    $scope.currentPage = 1;
    $scope.pageSize = 10;
    $scope.meals = [];

    var dishes = [
        'noodles',
        'sausage',
        'beans on toast',
        'cheeseburger',
        'battered mars bar',
        'crisp butty',
        'yorkshire pudding',
        'wiener schnitzel',
        'sauerkraut mit ei',
        'salad',
        'onion soup',
        'bak choi',
        'avacado maki'
    ];
    var sides = [
        'with chips',
        'a la king',
        'drizzled with cheese sauce',
        'with a side salad',
        'on toast',
        'with ketchup',
        'on a bed of cabbage',
        'wrapped in streaky bacon',
        'on a stick with cheese',
        'in pitta bread'
    ];
    for (var i = 1; i <= 100; i++) {
        var dish = dishes[Math.floor(Math.random() * dishes.length)];
        var side = sides[Math.floor(Math.random() * sides.length)];
        $scope.meals.push({ key: i, val: dish + ' ' + side });
    }

    $scope.pageChangeHandler = function (num) {
        console.log('meals page changed to ' + num);
    };
}

function OtherController($scope) {
    $scope.pageChangeHandler = function (num) {
        console.log('going to page ' + num);
    };
}

app.controller('MyController', MyController);
app.controller('OtherController', OtherController);
