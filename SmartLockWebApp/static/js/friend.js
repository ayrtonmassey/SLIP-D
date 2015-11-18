var users = new Bloodhound({
    datumTokenizer: function (d) {
        return Bloodhound.tokenizers.whitespace(d.name);
    },
    queryTokenizer: Bloodhound.tokenizers.whitespace,
    // url points to a json file that contains an array of country names, see
    // https://github.com/twitter/typeahead.js/blob/gh-pages/data/countries.json
    prefetch: '/users',
});

users.clear();
users.clearPrefetchCache();
users.initialize(true);

$('#friend-search .typeahead').typeahead(null, {
    name: 'search-friends',
    display: 'name',
    displayKey: 'name',
    hint: true,
    highlight: true,
    minLength: 1,
    source: users.ttAdapter(),
    templates: {
        empty: [
            '<div class="empty-message">',
            'No users found with that name.',
            '</div>'
        ].join('\n'),
        suggestion: function(d) {
            return '<p><strong>' + d.name + '</strong> <span class="pull-right"><a class="btn btn-primary btn-xs" href="profile/'+ d.id + '"><i class="fa fa-user"></i></a> <a class="btn ' + (d.is_friend ? 'btn-danger' : 'btn-success') + ' btn-xs" href="/friends/' + (d.is_friend ? 'remove' : 'add') + '/' + d.id + '"><i class="fa fa-' + (d.is_friend ? 'minus' : 'plus') + '"></i></a></span></p>';
        },
    }
}).bind('typeahead:selected', function(obj, selected, name) {
    $("#friend-search input[name='id']").prop('value',selected.id);
});
