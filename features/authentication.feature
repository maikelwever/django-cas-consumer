Feature: An authentication backend to validate a user via the remote CAS provider.

  Scenario: One existing user, one validated user
    Given an existing user
        And one user will be validated
        And a validation ticket
        And I am listening for CAS-related signals

    When I authenticate against the CAS client backend
        Then I receive the authenticated user
            And I receive the authentication signal


  Scenario: One existing user, two validated users
    Given an existing user
        And two users will be validated
        And a validation ticket
        And I am listening for CAS-related signals

    When I authenticate against the CAS client backend
        Then I receive the authenticated user
            And I receive the authentication signal


  Scenario: No existing user, one validated users
    Given no existing user
        And two users will be validated
        And a validation ticket
        And I am listening for CAS-related signals

    When I authenticate against the CAS client backend
        Then a user was created
            And I receive the authenticated user
            And I receive the authentication signal


  Scenario: Two existing users, two validated users
    Given two existing users
        And two users will be validated
        And a validation ticket
        And I am listening for CAS-related signals

    When I authenticate against the CAS client backend
        Then I receive the authenticated user
            And I receive the authentication signal
            And I receive the merge signal
