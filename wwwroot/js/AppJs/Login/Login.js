alert(5566);
alert(445);

function RedirectLogin() {
	window.location.href = "@Url.Action("Index", "DashBoard")";
	return false;
}

function OnFailure(data) {
	alert(JSON.stringify(data));
}

function OnSuccess(data) {
	alert(data.isUserExists)
	if (data.isUserExists == "Y") {
		window.location.href = '@Url.Action("Index", "Home")';
	}
	else {
		alert("Username or Password is Invalid !!!");
	}
}  